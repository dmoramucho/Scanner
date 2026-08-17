/**
 * The component system: one import site for the visual language.
 *
 * Screens import from here, never from the individual modules, so "which components exist" is
 * a question with one answer and a new screen cannot quietly invent a fourth way to render a
 * confidence state (m4-design §3).
 */
export { Badge } from './Badge';
export type { BadgeProps } from './Badge';

// The dictionary: every contract value mapped to its label, tokens and explanation.
export {
  CONFIDENCE_TREATMENTS,
  MANAGEMENT_TREATMENTS,
  PRIORITY_TREATMENTS,
  RECOMMENDATION_LABELS,
  REVIEW_TREATMENTS,
  VERSION_SOURCE_TREATMENTS,
  tone,
} from './treatments';
export type { Treatment } from './treatments';

// The three distinctions.
export { ConfidenceBadge } from './ConfidenceBadge';
export { ManagementBadge } from './ManagementBadge';
export { AiPanel, FactPanel } from './AiPanel';
export type { AiPanelProps, Citations } from './AiPanel';

// The recurring signals.
export { KevBadge } from './KevBadge';
export { PriorityBadge } from './PriorityBadge';
export { VersionSourceBadge } from './VersionSourceBadge';
export { InferredValue } from './InferredValue';
export { ReviewStateBadge } from './ReviewStateBadge';
