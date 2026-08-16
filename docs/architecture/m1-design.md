# M1 — Active Scanning & Credentialed Ground Truth

`docs/architecture/m1-design.md`

M0 gave us passive discovery, a scope gate, an observation spine, and entity resolution. M1 is the step where the scanner **emits packets at real devices** and **uses real credentials** — so it is where "don't break fragile devices" (AGENTS.md §2.7) and "read-only, secrets never logged" (§2.4, §2.10) stop being preparation and become operative against hardware.

Everything here is **brand-agnostic**: the core never knows "this is an Axis." It knows "this is a device with capability X," and a registry maps capabilities to adapters. A new vendor is a new adapter, never an `if brand == …` branch.

The value we add is **not the probing** (nmap has 25 years of solved edge cases — we orchestrate it, we don't reimplement it, per the functional architecture and AGENTS.md §78). Our code is the *judgment* layer on top: the per-device-class profile, the circuit breaker, and the normalization to CPE.

---

## 1. New ports (domain — no infra imports, AGENTS.md §2.1)

Three ports, each a seam an adapter plugs into.

### `ActiveScanner`
Uncredentialed reachability + service/version detection. Backed by an nmap-orchestrating adapter. The port speaks in **scan profiles and normalized results**, never in nmap flags — the flag translation lives entirely in the adapter.

```
ActiveScanner.scan(tenant_id, target, profile) -> ScanResult
```

- `profile: ScanProfile` — an enum of *intent* (`GENTLE`, `STANDARD`), not a bag of nmap options. The adapter maps intent to flags. `GENTLE` is the one that keeps fragile embedded stacks alive.
- `ScanResult` — normalized open ports, detected services, and inferred version signals, each already shaped as `ObservationInput` payloads (so the existing `ObservationSink` records them unchanged, with `version_source='banner'`).

### `CredentialedInspector`
Brand-agnostic ground-truth read from a device we can authenticate to. This is a **port**; the vendor/OS specifics live in adapters selected by a registry.

```
CredentialedInspector.inspect(tenant_id, target, credential_ref) -> InspectionResult
```

- `credential_ref` — an opaque reference resolved through the existing `SecretsPort`; the inspector receives a redacting `Secret`, never a raw string.
- `InspectionResult` — normalized software/firmware, shaped as `ObservationInput` with `version_source='package_manager'` (SSH package manager) or `'vendor_api'` (a manufacturer API adapter). **Read-only**: an inspector reads; it never configures.

### `InspectorRegistry`
Chooses the inspector for a device from its fingerprint capabilities — not its brand.

```
InspectorRegistry.for_device(fingerprint) -> CredentialedInspector | None
```

- Input is capability signals already produced by normalization (OUI, banner, whether a manufacturer API answered). Returns the matching adapter, or `None` when we have no credentialed path (the device stays uncredentialed — its observations keep `version_source='banner'`).
- M1 ships **one** adapter behind this: generic SSH. VAPIX/ISAPI/etc. are future adapters behind the same registry; the shape exists so adding one touches no core code.

---

## 2. Not breaking fragile devices (the heart of M1)

Active scanning of anything fingerprinted as embedded uses the **`GENTLE` profile**, and the adapter translates it to the flags we settled on earlier in design: no `-A`, no `--version-all`, `--version-intensity 0`, SYN not connect (`-sS`), `-T2` ceiling, `--scan-delay`, capped `--max-rate` and `--max-parallelism`, and a top-N IoT port set rather than all 65535. Servers get `STANDARD`. **The mapping from profile to flags lives in the nmap adapter and nowhere else.**

Two safety mechanisms live in the **engine**, above the adapter, so they are policy the adapter cannot forget:

- **Detect-then-adapt.** Classify by OUI/mDNS first (embedded-fragile vs robust), pick the profile, *then* scan. A device we can authenticate to skips aggressive probing entirely — logging in and reading is gentler and truer.
- **Circuit breaker.** A health check before and after touching each device; if it stops responding, abort the rest of the scan against *that device*, mark it, and back off. One unresponsive device never aborts the whole run (same shape as the passive sweep's per-target denial). Distress is first-class output, not a silent drop.

The scope gate still runs first, unchanged: `require_authorized` before any packet, for active scanning exactly as for passive.

---

## 3. Credentials against real devices

The `Secret` primitive and `SecretsPort` built in M0 now do real work. The rules, enforced in the credentialed adapters:

- The inspector resolves `credential_ref` through `SecretsPort` and holds a redacting `Secret`. The raw value reaches only the SSH/transport call, via `reveal()` — never a log, an error, or an `ObservationInput` payload.
- **Read-only is absolute.** The SSH adapter runs a fixed allowlist of read commands (`dpkg -l`, `rpm -q`, reading known firmware paths). No command that writes device or system state. No shell interpolation of untrusted data into the command (AGENTS.md §69).
- Command output is **untrusted input** (AGENTS.md §68): parsed and validated before it becomes an observation, never `eval`'d, never trusted for a filename or a query.
- Every credentialed access is auditable, like every scope decision.

---

## 4. Testing (fixtures for CI + a real target to validate)

- **CI runs against fixtures**, never a live network: recorded nmap XML output for the parser/normalizer, and recorded SSH command output for the SSH adapter. The nmap *binary* is not required in CI — the adapter is tested by feeding it captured XML, the profile→flags mapping is tested by asserting the built command, and the parser is tested against fixture XML. This keeps CI hermetic (AGENTS.md §43) and deterministic.
- **A real target validates separately**, outside CI, run by the operator: point the `GENTLE` profile at one real device on an authorized range and confirm it survives and the observation is correct. This is where "we don't break it" is actually proven — but it is a manual validation step, not a CI gate, because it needs real hardware and real authorization.
- The safety-critical assertions are the same style as M0: the profile→flags mapping for `GENTLE` **must** produce the gentle flags (a test that fails if someone loosens it), credentialed output never surfaces a secret, and the circuit breaker aborts on a simulated unresponsive device.

---

## 5. Tiering — what M1 is, and what it is not (AGENTS.md §5)

### In M1
- `ActiveScanner` port + nmap-orchestrating adapter, with `GENTLE`/`STANDARD` profiles.
- Engine: detect-then-adapt profile selection + circuit breaker, scope-gated.
- `CredentialedInspector` + `InspectorRegistry` ports.
- **One** credentialed adapter: generic SSH, read-only, using `SecretsPort`.
- `version_source` finally populated for real (`package_manager` / `banner`).
- Fixtures-based tests for all of the above; a documented manual real-target validation.

### Deferred (LATER — not M1)
- Additional credentialed adapters (VAPIX, ISAPI, embedded-BusyBox SSH) — future adapters behind the registry.
- The CPE→CVE correlation and NVD/KEV/EPSS — that is M3.
- Any active *exploitation* — never (AGENTS.md §2.6); M1 is enumeration only.
- Default-credential probing — remains opt-in and out of scope here.
- Live packet capture as a CI dependency — CI stays on fixtures.

---

## 6. Where this plugs into what exists

The output of both new ports is `ObservationInput` — so the **existing** `ObservationSink` records it (idempotent, provenance-complete) and the **existing** `AssetRepository` resolves it into assets. M1 adds *sources of observations*; it does not change the spine or the ER. Credentialed inspection is what finally feeds the ER `version_source='package_manager'` ground truth instead of only passive inference — the moat getting sharper, exactly as planned.

Build order (P-series continues from M0's P4):
1. **P5** — `ActiveScanner` port + nmap adapter (profile→flags, XML parsing, normalization to `ObservationInput`), fixtures-based tests. No engine wiring yet.
2. **P6** — engine: detect-then-adapt profile selection + circuit breaker, scope-gated; wire active scan → sink.
3. **P7** — `CredentialedInspector` + `InspectorRegistry` ports + the generic SSH adapter (read-only, `SecretsPort`, output parsing), fixtures-based tests.
4. **P8** — wire credentialed inspection into the ingestion path; `version_source` ground truth into the ER; the documented real-target validation runbook.
