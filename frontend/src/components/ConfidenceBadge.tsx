import { Badge } from './Badge';
import { CONFIDENCE_TREATMENTS, tone } from './treatments';
import type { ConfidenceState } from '../types/api';

/**
 * **Distinction 1 of 3: how well we know the version behind a finding.**
 *
 * The whole product rests on this being legible. `confirmed` came from the device's own
 * package database; `probable` came from a banner, and a distribution that backported the fix
 * serves the old version string forever — so a probable finding may already be patched
 * (AGENTS.md §3, ux-design §2).
 *
 * The component itself is four lines because the decisions live in `treatments.ts`, keyed by
 * the API's own union. There is no `switch`, no string comparison, and nowhere for a fourth
 * rendering of "probable" to appear.
 */
export function ConfidenceBadge({ state }: { state: ConfidenceState }) {
  const treatment = CONFIDENCE_TREATMENTS[state];
  return (
    <Badge kind="confidence" variant={state} tone={tone(treatment.tokens)} title={treatment.title}>
      {treatment.label}
    </Badge>
  );
}
