import { Badge } from './Badge';
import { REVIEW_TREATMENTS, tone } from './treatments';
import type { InsightState } from '../types/api';

/**
 * Where an insight sits in human review.
 *
 * Part of the fact-vs-AI distinction rather than a signal of its own: an AI panel must always
 * show its review state, because "a model suggested this" and "a person agreed with it" are
 * different claims and the interface is what keeps them apart (ux-design §2, AGENTS.md §2.8).
 */
export function ReviewStateBadge({ state }: { state: InsightState }) {
  const treatment = REVIEW_TREATMENTS[state];
  return (
    <Badge
      kind="review-state"
      variant={state}
      tone={tone(treatment.tokens)}
      title={treatment.title}
    >
      {treatment.label}
    </Badge>
  );
}
