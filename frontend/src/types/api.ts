/**
 * The API's contract, mirrored in TypeScript.
 *
 * These types are copied from the response models in `api/schemas.py` (P18/P19) and are the
 * single vocabulary the component system speaks. That matters more than it sounds: the three
 * distinctions the UI exists to make legible — confidence, management state, fact vs AI — are
 * *enum values the backend already decided*, and a component that matched on ad-hoc strings
 * could drift from them silently. Everything below is a union, and every component that
 * renders one maps it through an exhaustive `Record<Union, …>`, so adding a state to the
 * backend breaks the build here rather than rendering as a blank badge (m4-design §3).
 *
 * Kept by hand rather than generated. A generator would be the right call at ten times this
 * size; at this size it is a build step to maintain for six unions that change when the
 * contract changes — which is exactly when a human should look at them anyway.
 */

/** How the installed version behind a finding was established (AGENTS.md §3). */
export type ConfidenceState = 'confirmed' | 'probable' | 'verified_exploitable';

/** Where a version came from. `banner` is why `probable` exists. */
export type VersionSource = 'package_manager' | 'vendor_api' | 'banner';

/** Whether anything in the estate manages this asset (ADR-0009). */
export type ManagementState = 'managed' | 'unmanaged' | 'unknown';

/** The worklist band, derived by rule and carrying its reason (ADR-0015). */
export type Priority = 'p1' | 'p2' | 'p3' | 'p4';

export type AssetClass = 'server' | 'embedded' | 'application' | 'network_device' | 'unknown';

export type Reachability = 'internet_facing' | 'internal_only' | 'isolated_segment' | 'unknown';

/** What an insight may recommend. `lower_priority` is the only suppressing direction. */
export type Recommendation = 'raise_priority' | 'lower_priority' | 'maintain';

/** The review lifecycle. An insight is advisory until a human moves it (AGENTS.md §2.8). */
export type InsightState = 'proposed' | 'human_reviewed' | 'accepted';

/** The analyst's decision on an insight. */
export type ReviewOutcome = 'accepted' | 'rejected' | 'adjusted';

/** How a fact came to exist. The value that separates deterministic data from AI output. */
export type Derivation = 'deterministic' | 'llm_proposed' | 'llm_generated';

/**
 * The tuple forms exist so an exhaustive map can be *iterated* as well as type-checked —
 * the gallery and the tests render every state without a hand-maintained second list.
 */
export const CONFIDENCE_STATES = [
  'confirmed',
  'probable',
  'verified_exploitable',
] as const satisfies readonly ConfidenceState[];

export const MANAGEMENT_STATES = [
  'managed',
  'unmanaged',
  'unknown',
] as const satisfies readonly ManagementState[];

export const PRIORITIES = ['p1', 'p2', 'p3', 'p4'] as const satisfies readonly Priority[];

export const VERSION_SOURCES = [
  'package_manager',
  'vendor_api',
  'banner',
] as const satisfies readonly VersionSource[];

export const INSIGHT_STATES = [
  'proposed',
  'human_reviewed',
  'accepted',
] as const satisfies readonly InsightState[];

export const RECOMMENDATIONS = [
  'raise_priority',
  'lower_priority',
  'maintain',
] as const satisfies readonly Recommendation[];

/** `GET /api/worklist` → `findings[]`, and the finding list on an asset. */
export interface Finding {
  match_id: string;
  asset_id: string;
  asset_label: string | null;
  asset_class: AssetClass;
  management_state: ManagementState;
  cve_id: string;
  matched_cpe: string;
  priority: Priority;
  /** The id of the rule that produced the band (ADR-0015). */
  priority_rule: string;
  /** The sentence an analyst reads. Never re-derived in the client. */
  priority_reason: string;
  confidence_state: ConfidenceState;
  version_source: VersionSource;
  kev: boolean;
  epss: number | null;
  cvss_score: number | null;
  cvss_version: string | null;
  matched_at: string;
  has_insight: boolean;
}

/** A value the backend *derived* rather than measured — the VLAN label, today (ADR-0015). */
export interface ObservedValue {
  value: string;
  /** True ⇒ never render this as ground truth. */
  inferred: boolean;
  provenance: {
    source: string;
    source_type: string;
    collector: string;
    collection_method: string;
    confidence: number;
    observed_at: string;
    derivation: string;
  };
}

export interface SoftwareComponent {
  name: string;
  cpe: string | null;
  version: string | null;
  version_source: VersionSource;
  confidence: number;
}

/** One thing an insight grounded on. An insight without at least one of these is invalid. */
export interface Citation {
  kind: 'advisory' | 'dossier_field';
  ref: string;
  quote: string | null;
}

/** `GET /api/worklist` → `review_queue[]`. */
export interface InsightSummary {
  insight_id: string;
  asset_id: string;
  asset_label: string | null;
  cve_id: string;
  recommendation: Recommendation;
  confidence: number;
  state: InsightState;
  /** True ⇒ this finding stays visible whatever anyone recommends (AGENTS.md §2.8). */
  kev_locked_visible: boolean;
  model_version: string;
  created_at: string;
  derivation: 'llm_generated';
}

export interface WorklistSummary {
  kev_findings: number;
  p1_findings: number;
  needs_verification: number;
  proposed_insights: number;
  shadow_it_assets: number;
  /** Reported apart from shadow IT, because ambiguous is not the same claim (ADR-0009). */
  unknown_management_assets: number;
  total_findings: number;
}

export interface Worklist {
  summary: WorklistSummary;
  findings: Finding[];
  needs_verification: Finding[];
  review_queue: InsightSummary[];
}

export interface ReviewEvent {
  kind: 'accept' | 'reject' | 'adjust' | 'state_change';
  from_state: InsightState;
  to_state: InsightState;
  reviewer: string;
  recommendation: Recommendation | null;
  rationale: string | null;
  occurred_at: string;
}
