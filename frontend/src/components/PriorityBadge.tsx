import { Badge } from './Badge';
import { PRIORITY_TREATMENTS, tone } from './treatments';
import type { Priority } from '../types/api';
import './priority.css';

/**
 * The worklist band — and, always, the reason it was given.
 *
 * P17 made priority explainable: every finding carries the id of the rule that produced its
 * band and a sentence naming the evidence ("CISA lists CVE-… as known exploited"). This
 * component's job is to never separate the two. The reason is the title, so it is one hover
 * away everywhere, and `showReason` puts it inline where there is room.
 *
 * The band is **never computed here**. Recomputing it in the client would be a second
 * implementation of the policy, and the two would drift — with the interface's version
 * winning, because it is the one people see (ADR-0015).
 */
export interface PriorityBadgeProps {
  priority: Priority;
  /** The sentence from the API. Required: a band without its reason is the thing we replaced. */
  reason: string;
  /** The rule id, for the analyst who wants to know which rule fired. */
  rule?: string;
  showReason?: boolean;
}

export function PriorityBadge({ priority, reason, rule, showReason = false }: PriorityBadgeProps) {
  return (
    <span className="priority" data-kind="priority-group">
      <Badge
        kind="priority"
        variant={priority}
        tone={tone(`priority-${priority}`)}
        title={rule ? `${reason} (rule: ${rule})` : reason}
        detail={PRIORITY_TREATMENTS[priority].meaning}
      >
        {PRIORITY_TREATMENTS[priority].label}
      </Badge>
      {showReason ? (
        <span className="priority__reason" data-testid="priority-reason">
          {reason}
        </span>
      ) : null}
    </span>
  );
}
