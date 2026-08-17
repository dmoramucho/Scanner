import type { Citation, Finding, InsightSummary, ObservedValue, Worklist } from '../types/api';

/**
 * Mock data, typed against the API contract.
 *
 * Every fixture below is a `Finding`, an `InsightSummary` or a `Worklist` — the same types
 * `fetch` will produce in P21 — so the gallery is not a drawing of what the components might
 * receive. When the real API arrives, the fixtures are deleted and nothing else changes.
 */

export const CITATIONS: readonly [Citation, ...Citation[]] = [
  {
    kind: 'advisory',
    ref: 'CVE-2023-25690',
    quote: 'allow a HTTP Request Smuggling attack',
  },
  { kind: 'dossier_field', ref: 'exposure.reachability.value', quote: null },
];

export const KEV_FINDING: Finding = {
  match_id: '4d1b1f6a-0d1f-4a1a-9a6f-2f5a3b7c8d90',
  asset_id: 'a1b2c3d4-0000-4000-8000-000000000001',
  asset_label: 'cam-lobby-01',
  asset_class: 'embedded',
  management_state: 'unmanaged',
  cve_id: 'CVE-2023-25690',
  matched_cpe: 'cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*',
  priority: 'p1',
  priority_rule: 'kev-actively-exploited',
  priority_reason:
    'CISA lists CVE-2023-25690 as known exploited — attackers are using it now, so it is P1 ' +
    'regardless of how the version was identified.',
  confidence_state: 'confirmed',
  version_source: 'package_manager',
  kev: true,
  epss: 0.42,
  cvss_score: 9.8,
  cvss_version: '3.1',
  matched_at: '2026-08-16T04:12:00Z',
  has_insight: true,
};

export const PROBABLE_FINDING: Finding = {
  ...KEV_FINDING,
  match_id: '7c2e0a11-1111-4111-8111-111111111111',
  asset_id: 'a1b2c3d4-0000-4000-8000-000000000002',
  asset_label: 'app-server-02',
  asset_class: 'server',
  management_state: 'managed',
  cve_id: 'CVE-2024-27316',
  priority: 'p3',
  priority_rule: 'probable-severe-unverified',
  priority_reason:
    'CVE-2024-27316 would matter if it is really installed, but the version is inferred from ' +
    'a banner and may already be patched by a backport. It belongs in the verification queue.',
  confidence_state: 'probable',
  version_source: 'banner',
  kev: false,
  epss: 0.02,
  cvss_score: 8.1,
  has_insight: false,
};

export const AMBIGUOUS_FINDING: Finding = {
  ...PROBABLE_FINDING,
  match_id: '9f3d2b55-2222-4222-8222-222222222222',
  asset_id: 'a1b2c3d4-0000-4000-8000-000000000003',
  asset_label: 'printer-3f',
  management_state: 'unknown',
  cve_id: 'CVE-2024-0001',
  priority: 'p4',
  priority_rule: 'probable-unverified',
  priority_reason:
    'The version is inferred from a banner and may already be patched by a backport, and ' +
    'CVE-2024-0001 is neither severe nor likely to be exploited.',
  cvss_score: 4.2,
  epss: null,
};

export const PROPOSED_INSIGHT: InsightSummary = {
  insight_id: 'b7e6d5c4-3333-4333-8333-333333333333',
  asset_id: KEV_FINDING.asset_id,
  asset_label: KEV_FINDING.asset_label,
  cve_id: KEV_FINDING.cve_id,
  recommendation: 'raise_priority',
  confidence: 0.82,
  state: 'proposed',
  kev_locked_visible: true,
  model_version: 'llama3.3:70b',
  created_at: '2026-08-16T05:03:00Z',
  derivation: 'llm_generated',
};

export const INFERRED_VLAN: ObservedValue = {
  value: 'VLAN 60 (IoT)',
  inferred: true,
  provenance: {
    source: 'subnet_vlan_map',
    source_type: 'inferred',
    collector: 'dossier-assembler',
    collection_method: 'subnet_containment',
    confidence: 0.6,
    observed_at: '2026-08-16T04:12:00Z',
    derivation: 'deterministic',
  },
};

export const WORKLIST: Worklist = {
  summary: {
    kev_findings: 1,
    p1_findings: 1,
    needs_verification: 2,
    proposed_insights: 1,
    shadow_it_assets: 1,
    unknown_management_assets: 1,
    total_findings: 3,
  },
  findings: [KEV_FINDING, PROBABLE_FINDING, AMBIGUOUS_FINDING],
  needs_verification: [PROBABLE_FINDING, AMBIGUOUS_FINDING],
  review_queue: [PROPOSED_INSIGHT],
};

export const RATIONALE =
  'The advisory describes request smuggling reachable through mod_proxy, and this host is ' +
  'internet-facing on an IoT segment, so the affected path is exposed.';
