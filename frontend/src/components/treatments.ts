import type {
  ConfidenceState,
  InsightState,
  ManagementState,
  Priority,
  Recommendation,
  VersionSource,
} from '../types/api';

/**
 * Every contract value, and what it looks like. One file.
 *
 * This is the component system's dictionary: for each union the API sends, an exhaustive
 * `Record` giving the label an analyst reads, the token trio that colours it, and the sentence
 * that explains it. Keeping them together rather than beside their components is deliberate —
 * the question "is the language consistent?" should be answerable by reading one screen of
 * code, and drift is easiest to spot when the entries sit next to each other (m4-design §3).
 *
 * Two rules hold throughout:
 *
 * - **Keyed by the API's own unions.** A state added to the backend is a compile error here,
 *   not a blank badge in production.
 * - **Tokens, never colours.** Each entry names a token prefix; `tokens.css` decides what that
 *   means. `src/theme/tokens.test.ts` fails the build on a literal colour anywhere.
 */

export interface Treatment {
  /** What an analyst reads. */
  label: string;
  /** The token prefix — `confidence-probable` → `--confidence-probable-{fg,bg,border}`. */
  tokens: string;
  /** What the label means, on hover and to assistive technology. */
  title: string;
  /** A leading glyph, where the signal carries one. */
  mark?: string;
}

/** Build a badge tone from a token prefix, so components name meanings rather than colours. */
export function tone(prefix: string): { fg: string; bg: string; border: string } {
  return {
    fg: `var(--${prefix}-fg)`,
    bg: `var(--${prefix}-bg)`,
    border: `var(--${prefix}-border)`,
  };
}

/**
 * Distinction 1 — how well we know the version.
 *
 * Probable is amber, not red: it is a work queue ("verify by logging in"), and a backported
 * fix leaves the old banner in place. Dressing it as an alarm puts a maybe-false-positive
 * beside a real finding, which is the noise this product exists to remove (ux-design §2).
 */
export const CONFIDENCE_TREATMENTS: Record<ConfidenceState, Treatment> = {
  confirmed: {
    label: 'Confirmed',
    tokens: 'confidence-confirmed',
    title: "Confirmed from the device's own package database — ground truth.",
  },
  probable: {
    label: 'Probable',
    tokens: 'confidence-probable',
    title:
      'Inferred from a service banner. The fix may already be backported — verify by ' +
      'logging in before acting.',
  },
  verified_exploitable: {
    label: 'Verified exploitable',
    tokens: 'confidence-verified',
    title: 'Exploitability was demonstrated on this asset — the strongest evidence there is.',
  },
};

/**
 * Distinction 2 — does anything manage this device.
 *
 * Shadow IT is the headline and the only one with real colour. Unknown stays grey: the
 * reconciliation refuses to count an ambiguous match as shadow IT, and a red badge would make
 * the same overclaim visually (ADR-0009).
 */
export const MANAGEMENT_TREATMENTS: Record<ManagementState, Treatment> = {
  managed: {
    label: 'Managed',
    tokens: 'management-managed',
    title: 'Known to at least one managed source (AD, MDM, EDR, vCenter, CMDB).',
  },
  unmanaged: {
    label: 'Shadow IT',
    tokens: 'management-shadow',
    title: 'On the network and known to no managed source — nobody is looking after it.',
  },
  unknown: {
    label: 'Unknown',
    tokens: 'management-unknown',
    title:
      'The managed-record match was ambiguous, so management state could not be established. ' +
      'Deliberately not counted as shadow IT.',
  },
};

/** How a version was established — the evidence behind the confidence badge (AGENTS.md §3). */
export const VERSION_SOURCE_TREATMENTS: Record<VersionSource, Treatment> = {
  package_manager: {
    label: 'Credentialed',
    tokens: 'source-ground-truth',
    mark: '🔑',
    title: "Read from the device's own package database over an authenticated session.",
  },
  vendor_api: {
    label: 'Vendor API',
    tokens: 'source-ground-truth',
    mark: '🔑',
    title: "Read from the manufacturer's own API — the vendor stating its firmware version.",
  },
  banner: {
    label: 'Banner',
    tokens: 'source-inferred',
    mark: '~',
    title:
      'Inferred from a service banner. A backported fix leaves the old version string in ' +
      'place, so this may be a false positive until verified.',
  },
};

/**
 * Where an insight sits in human review. Part of the fact-vs-AI distinction: "a model
 * suggested this" and "a person agreed" are different claims (AGENTS.md §2.8).
 */
export const REVIEW_TREATMENTS: Record<InsightState, Treatment> = {
  proposed: {
    label: 'Awaiting review',
    tokens: 'confidence-probable',
    title: 'A model proposed this. No human has looked at it yet.',
  },
  human_reviewed: {
    label: 'Reviewed',
    tokens: 'management-unknown',
    title: 'A human has read this and not accepted it.',
  },
  accepted: {
    label: 'Accepted',
    tokens: 'management-managed',
    title: 'A human read this and agreed with it.',
  },
};

/** The band, and what an analyst is meant to do about it (ADR-0015). */
export const PRIORITY_TREATMENTS: Record<Priority, Treatment & { meaning: string }> = {
  p1: { label: 'P1', tokens: 'priority-p1', meaning: 'Act now', title: 'Act now.' },
  p2: { label: 'P2', tokens: 'priority-p2', meaning: 'Schedule', title: 'Schedule.' },
  p3: { label: 'P3', tokens: 'priority-p3', meaning: 'Plan / verify', title: 'Plan or verify.' },
  p4: { label: 'P4', tokens: 'priority-p4', meaning: 'Informational', title: 'Informational.' },
};

/** What a model may recommend. Advisory in every case — a human decides (AGENTS.md §2.8). */
export const RECOMMENDATION_LABELS: Record<Recommendation, string> = {
  raise_priority: 'Raise priority',
  lower_priority: 'Lower priority',
  maintain: 'Maintain priority',
};
