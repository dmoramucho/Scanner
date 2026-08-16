# Runbook — validating a GENTLE scan against one real device

`docs/runbooks/validate-gentle-scan.md` · owner: whoever runs the scan · **not a CI test**

---

## Why this exists

Every other safety claim in this system is proven by a test. This one cannot be.

The test suite proves that the `GENTLE` profile *builds* a gentle command — no `-A`, no
`--version-all`, `--version-intensity 0`, SYN not connect, `-T2`, a scan delay, capped rate and
parallelism, a curated port set (`tests/test_nmap_profiles.py`). It proves the circuit breaker
reacts when a device stops answering (`tests/test_active_scan_engine.py`). It proves the scope
gate refuses an unauthorised target.

**None of that proves an actual camera survives an actual scan.** Fixtures cannot. The only way
to know is to point the thing at one real device, under real authorisation, and watch —
carefully, once, with a way to stop.

That is what this procedure is. It is the moment AGENTS.md §2.7 ("do not break embedded
devices") stops being a design principle and becomes an observed fact about your estate. Treat
it as a change to production, because that is what it is: you are sending packets at hardware
someone depends on.

> **The failure mode you are guarding against is not a bad scan result. It is a camera that
> stops recording, a VoIP phone that drops a call, a badge reader that stops opening a door.**
> If any of those is unacceptable right now, stop and come back during a window where it is not.

---

## 0. Before you start: authorisation

Do not skip this section. The scope gate enforces the *technical* control; this section is the
*organisational* one, and the gate is only as meaningful as the authorisation behind it.

- [ ] **Written authorisation exists** for scanning the range that contains your target, and you
      can point at it — a ticket, a signed engagement letter, a documented standing approval.
      You will record its reference in the database in step 2. If there is nothing to reference,
      you are not authorised, and the correct action is to stop.
- [ ] **The device owner knows.** Whoever operates this camera / phone / printer has agreed to
      the window. Name and contact to hand.
- [ ] **You have a rollback contact** — the person who can power-cycle the device physically if
      it stops responding and does not come back.
- [ ] **The window is right.** Not during a shift change if it is a badge reader; not during
      business hours if it is a conference-room phone; not while the camera is covering
      something that matters.
- [ ] **Record the change.** Whatever your change-management process is, this goes in it.

---

## 1. Pick the device

Choose deliberately. This is the one you are most willing to lose.

**Good first target:**
- A device you can physically reach and power-cycle within minutes.
- Low consequence if it reboots: a spare camera, a lab printer, a bench phone, a decommissioned
  UPS still on the network.
- Representative enough to be informative — same vendor and firmware family as devices you will
  eventually scan for real.

**Do not start with:**
- Anything in a safety or life-safety path (door controllers, fire panels, medical devices,
  industrial controllers). These are out of scope for a first validation, full stop.
- Anything you cannot physically reach.
- Anything currently in use for something that matters.
- Anything you have no owner for.

Write down: address, MAC, vendor, model, firmware version, what it does, who owns it.

```bash
# What we already know about it from passive discovery — no packets required.
docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    select kind, value, last_seen_at
    from asset_identifier
    where tenant_id = '<TENANT_UUID>' and value = '<TARGET_IP>';"
```

---

## 2. Register the scope authorisation

Nothing can be scanned until the range is registered and active. This is deny-by-default: the
absence of a row is a refusal, and that is the intended state until you deliberately change it.

Register **the narrowest range that contains your target** — a `/32`, i.e. that one address.
Do not register the whole subnet for a single-device validation.

```bash
set -a; . ./.env; set +a

docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    insert into scope_authorization
        (tenant_id, cidr, written_auth_ref, active, authorized_at, expires_at)
    values (
        '<TENANT_UUID>',
        '<TARGET_IP>/32',
        '<TICKET-OR-ENGAGEMENT-REF>',       -- the written authorisation from step 0
        true,
        now(),
        now() + interval '4 hours'          -- expires on its own; see step 7
    ) returning id, cidr, expires_at;"
```

Two things to notice, both deliberate:

- **`/32`.** The blast radius of a mistake in the next steps is exactly one device.
- **`expires_at`.** The authorisation switches itself off. If you are distracted and never get to
  the rollback step, the window closes anyway — `PostgresScopeAuthority` treats an expired
  authorisation as no authorisation.

**Verify the gate agrees before going further.** A denial here is the system working; an
unexpected *allow* means you have registered more than you think:

```bash
docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    select id, cidr from scope_authorization
    where tenant_id = '<TENANT_UUID>'
      and active and (expires_at is null or expires_at > now())
      and cidr >>= '<TARGET_IP>'::inet;"     -- expect exactly one row: your /32

docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    select count(*) as should_be_zero from scope_authorization
    where tenant_id = '<TENANT_UUID>'
      and active and (expires_at is null or expires_at > now())
      and cidr >>= '<A-NEIGHBOURING-IP>'::inet;"
```

---

## 3. Baseline the device — before you touch it

You cannot tell whether a scan hurt something if you do not know what healthy looked like ten
minutes earlier. Capture all of these and keep them on screen:

- [ ] **Ping response and latency.** `ping -c 20 <TARGET_IP>` — record loss and average RTT.
- [ ] **Which TCP port is open**, and note it: the breaker's probe connects to one port you
      name (step 4), so you need to know one. The camera's 80 or 554, the printer's 9100, the
      phone's 80 — whatever step 1's passive data or the device's own admin UI tells you.
- [ ] **Its actual job, working.** Pull up the camera's video stream; make a test call on the
      phone; print a test page. *"It answers pings" is not "it works."* Most embedded failures
      under scan look like a live ping and a dead application.
- [ ] **Admin UI loads**, and note the firmware version it reports.
- [ ] **Uptime**, if the device shows it. This is the single most useful number you will have: a
      reset uptime afterwards is unambiguous evidence of a reboot.
- [ ] **Device logs**, if reachable — note the last entry so you can spot new ones.

Leave `ping -i 1 <TARGET_IP>` running in its own terminal for the whole exercise. It is your
live health signal.

---

## 4. Run the scan — one target, GENTLE, watched

There is no CLI yet (see *Known gaps*), so this is a short script. It wires the same components
the engine uses in production: the scope gate, the nmap adapter, the circuit breaker.

The scanner needs raw-socket privileges for `-sS` (root or `CAP_NET_RAW`). It will *not* fall
back to a connect scan — a connect scan completes the handshake and leaves application-layer
state on the device, which is the thing that wedges fragile stacks (ADR-0003).

```python
# validate_one_device.py — run with: sudo -E uv run python validate_one_device.py
from ipaddress import ip_address
from uuid import UUID, uuid4

import psycopg

from adapters.postgres.asset_repository import PostgresAssetRepository
from adapters.postgres.observation_sink import PostgresObservationSink
from adapters.postgres.scope_authority import PostgresScopeAuthority
from adapters.probe.tcp import TcpHealthProbe
from adapters.scanner.nmap import NmapActiveScanner
from config import load_config
from engine.active_scan import ActiveScanEngine, BreakerPolicy, ScanCandidate, classify

TENANT = UUID("<TENANT_UUID>")
TARGET = ip_address("<TARGET_IP>")

candidate = ScanCandidate(
    target=TARGET,
    mac_vendor="<VENDOR FROM STEP 1>",   # e.g. "Axis Communications AB"
    open_ports=(),                       # leave empty; let the vendor decide the profile
)

# The breaker's health check: one TCP connect to a port you know is open on this device
# (its admin UI, its RTSP stream — whatever answered in step 3), then close. No data is
# sent. If you have no known-open port, the probe refuses to guess and the device is not
# scanned (ADR-0007) — find the port first, or do not scan it yet.
probe = TcpHealthProbe({str(TARGET): <KNOWN_OPEN_PORT>}, timeout_seconds=2.0)

# Confirm the probe agrees the device is alive BEFORE the scan. This is the same call the
# breaker makes, so a False here means the breaker would refuse to scan anyway.
print("responsive before scan:", probe.is_responsive(TARGET))

# Confirm the profile BEFORE any packet. If this does not print GENTLE, stop and fix the
# classification rather than proceeding.
print("profile:", classify(candidate))

run_id = uuid4()
with psycopg.connect(load_config().database_url.reveal(), autocommit=True) as conn:
    engine = ActiveScanEngine(
        PostgresScopeAuthority(conn, actor="operator", correlation_id="gentle-validation"),
        NmapActiveScanner(run_id),
        probe,
        PostgresObservationSink(conn),
        PostgresAssetRepository(conn),
        run_id=run_id,
        breaker=BreakerPolicy(health_check_attempts=2, backoff_seconds=30.0),
    )
    outcome = engine.run(TENANT, [candidate])

print(outcome)
```

**While it runs:** watch the ping window, and watch the device's real function (the video
stream, the call, the display). A `GENTLE` scan of ~30 ports at a 200 ms delay takes a few
minutes. That slowness is the safety mechanism; do not "just speed it up to check".

**Stop immediately — `Ctrl-C` — if any of these happen:**

- Ping latency climbs sharply or packets start dropping.
- The video stream stutters or drops; the call degrades; the display blanks.
- The admin UI stops loading or gets slow.
- The device reboots (watch for uptime resetting).
- Anything else surprises you. You do not need a reason more specific than that.

---

## 5. Check the device afterwards — the same checks as step 3

Immediately after the scan finishes (or after you stop it):

- [ ] Ping still healthy, latency back to baseline.
- [ ] **Its actual job still works** — the stream, the call, the print. Check this properly, not
      just that it answers.
- [ ] Admin UI loads; firmware version unchanged.
- [ ] **Uptime has not reset.** A reset uptime means it rebooted. That is a failure, even if
      everything works now.
- [ ] No new error entries in the device log.
- [ ] Leave the ping running for another 10 minutes. Some embedded stacks fall over a little
      after the pressure ends, not during it.

### What "it survived and the observation is correct" looks like

**Survival** — every box in this section ticked, and `outcome.tripped == 0`. If the breaker
tripped, the engine already recorded it and backed off; treat that as a failure of the profile
for this device class regardless of how the device looks now.

**Correctness** — the scan actually learned something true:

```bash
docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    select observation_type, source, source_type, collection_method,
           version_source, confidence, observed_at, payload
    from observation
    where tenant_id = '<TENANT_UUID>' and source_identifier = '<TARGET_IP>'
    order by ingested_at desc limit 10;"
```

Confirm:
- [ ] `collection_method` is **`nmap_gentle`** — the profile you intended is the one that ran.
- [ ] The open ports match reality (the camera's 80/554 are there; nothing absurd).
- [ ] Any version signal carries `version_source = 'banner'` — an uncredentialed scan infers, and
      the row says so (AGENTS.md §3).
- [ ] Every provenance column is populated; `observed_at` and `collected_at` are sane.
- [ ] The device resolved into **one** asset, not a new duplicate:

```bash
docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    select a.id, a.status, count(i.id) as identifiers
    from asset a join asset_identifier i on i.asset_id = a.id
    where a.tenant_id = '<TENANT_UUID>' and i.value in ('<TARGET_IP>', '<TARGET_MAC>')
    group by a.id, a.status;"
```

A scan that ran gently but produced nothing useful is also a failure — of usefulness, not of
safety. Record it as such: the port set may need adjusting for this device class.

---

## 6. If the device shows distress

**Right now, in order:**

1. **Stop the scan.** `Ctrl-C`. The engine aborts the current target; the breaker will already
   have backed off if it noticed first.
2. **Deactivate the authorisation** so nothing can touch it again while you work:

   ```bash
   docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres \
     psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
       update scope_authorization set active = false
       where tenant_id = '<TENANT_UUID>' and cidr = '<TARGET_IP>/32';"
   ```

   Revocation takes effect on the next decision — no restart, no cache.
3. **Wait five minutes before touching it.** Many embedded stacks recover on their own once the
   pressure stops. Piling on diagnostics is more of the same pressure.
4. **Still down? Power-cycle it** — your step 0 rollback contact. This is why the first target
   had to be one you can physically reach.
5. **Tell the device owner.** Immediately, whether or not it recovered.

**Then, before anyone tries again:**

- [ ] Record what happened: device, vendor, model, firmware, exact `collection_method`, what
      failed, how long it took to recover.
- [ ] Check the trip in the store — the engine records distress as evidence, not just a counter:

      ```sql
      select payload, observed_at from observation
      where tenant_id = '<TENANT_UUID>' and observation_type = 'device_health'
      order by ingested_at desc limit 5;
      ```
- [ ] **Do not retry the same profile on the same device class.** `GENTLE` was not gentle enough
      for this hardware, which is a finding — an important one. It means this device class needs
      a credentialed path (P7: logging in and reading is gentler and truer) or passive-only
      treatment.
- [ ] Open the question of whether `GENTLE` needs tightening for everyone, or whether this class
      needs its own profile. That is an ADR-0004 amendment, not a quiet tweak.

---

## 7. Close out

Whatever the result:

- [ ] **Deactivate or let the authorisation expire.** If you set `expires_at`, confirm it has
      passed; otherwise deactivate explicitly (step 6.2). Do not leave a standing authorisation
      behind after a validation.

  ```bash
  docker compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
      select cidr, active, expires_at from scope_authorization
      where tenant_id = '<TENANT_UUID>' and active
        and (expires_at is null or expires_at > now());"     -- expect: nothing for this device
  ```
- [ ] **Confirm the audit trail** — every decision is on the record, and this is the artifact you
      show someone who asks what you did:

  ```sql
  select occurred_at, result, resource_id, actor, metadata
  from audit_log
  where tenant_id = '<TENANT_UUID>' and action = 'scope.authorize'
  order by occurred_at desc limit 20;
  ```
- [ ] **Write down the result** against the device class: vendor, model, firmware, survived
      yes/no, observation quality, date, who ran it. This is the beginning of the table that
      tells you which of your device classes are safe to scan, and it is worth more than any
      single scan result.
- [ ] Tell the device owner it is done.

Only after a device class has passed this once should scanning be widened to more devices of
that class — and even then, in small batches with the breaker on.

---

## Known gaps in this procedure

Stated plainly rather than left for you to discover mid-validation:

- **No CLI.** Step 4 is a script because no operator entry point exists yet. It needs one.
- **The probe needs a port you supply.** `TcpHealthProbe` connects to a port discovery already
  found open; it will not scan to find one, and it raises rather than assuming health if it has
  none (ADR-0007). For a device whose ports you do not yet know, that means the breaker refuses
  and the device is not scanned — deliberately, but it is friction worth knowing about before
  you are standing in front of the rack.
- **A TCP probe cannot see an application dying.** A device whose kernel still answers a SYN
  while its video stream is dead reads as "responsive". That is why step 3 and step 5 ask you to
  check the device's *actual job*, not just its liveness — the human check is still the better
  instrument, and the probe complements it rather than replacing it.
- **`GENTLE` is untested against real hardware.** That is the entire point of this document; the
  first person to run it is doing the validation, not confirming it.
- **Credentialed inspection has its own unrun validation.** The SSH inspector (P7) needs the same
  treatment — a first real device, read-only commands, watched — plus a known-hosts provisioning
  step, since unknown host keys are rejected by design (ADR-0005). That runbook is owed.
