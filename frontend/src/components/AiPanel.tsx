import type { ReactNode } from 'react';
import { Badge } from './Badge';
import { RECOMMENDATION_LABELS, tone } from './treatments';
import { ReviewStateBadge } from './ReviewStateBadge';
import type { Citation, InsightState, Recommendation } from '../types/api';
import './AiPanel.css';

/**
 * **Distinction 3 of 3: this was written by a model.**
 *
 * The most consequential of the three, and the one the backend spent a whole milestone
 * containing. An insight is *advisory*, *grounded* and *reviewable*, and the UI has to make
 * all three visible at a glance: a tinted surface with a coloured rule, a header that says
 * AI-GENERATED in words, and — always — the citations, the model's confidence, and where the
 * insight sits in human review (ux-design §2, m4-design §3).
 *
 * **Citations are a required prop, and the type is a non-empty tuple.** An insight with no
 * grounding is rejected by the generator, refused by the store and refused by a database
 * CHECK (ADR-0014). This is the same rule expressed in the type system: you cannot compile a
 * call that renders AI content with an empty citation list. The UI does not *enforce*
 * grounding — the backend does — but it also cannot be the place where an ungrounded claim
 * gets rendered as if it were fine.
 *
 * A KEV-locked insight says so in the header, because that is the one thing the recommendation
 * below it cannot change (AGENTS.md §2.8).
 */

/** At least one. The compiler is the check. */
export type Citations = readonly [Citation, ...Citation[]];

export interface AiPanelProps {
  /** The model's recommendation. Advisory: a human decides (AGENTS.md §2.8). */
  recommendation: Recommendation;
  /** The model's own confidence, 0–1. Its opinion of itself, and labelled as such. */
  confidence: number;
  /** Where this insight sits in review. */
  state: InsightState;
  /** What it grounded on. Never empty — see above. */
  citations: Citations;
  /** True ⇒ the finding stays visible whatever this recommends. */
  kevLocked?: boolean;
  /** Which model produced it, so an insight can be read against the model that wrote it. */
  modelVersion?: string;
  children: ReactNode;
}

export function AiPanel({
  recommendation,
  confidence,
  state,
  citations,
  kevLocked = false,
  modelVersion,
  children,
}: AiPanelProps) {
  return (
    <section className="ai-panel" data-kind="ai" data-derivation="llm_generated">
      <header className="ai-panel__header">
        <span className="ai-panel__label">AI-generated</span>
        <Badge kind="recommendation" variant={recommendation} tone={tone('ai')}>
          {RECOMMENDATION_LABELS[recommendation]}
        </Badge>
        <Badge
          kind="ai-confidence"
          variant="model-confidence"
          tone={tone('ai')}
          title="The model's confidence in its own reasoning — not a measurement."
        >
          {`Model confidence ${(confidence * 100).toFixed(0)}%`}
        </Badge>
        {kevLocked ? (
          <Badge
            kind="kev-lock"
            variant="locked"
            tone={tone('signal-kev')}
            mark="🔒"
            loud
            title="Actively exploited: this finding stays visible whatever the insight recommends."
          >
            KEV locked visible
          </Badge>
        ) : null}
        <span className="ai-panel__spacer" />
        <ReviewStateBadge state={state} />
      </header>

      <div className="ai-panel__body">{children}</div>

      <ul className="ai-panel__citations" aria-label="Citations">
        <li className="ai-panel__citations-label">
          Grounded in {citations.length} source{citations.length === 1 ? '' : 's'}
        </li>
        {citations.map((citation) => (
          <li className="ai-panel__citation" key={`${citation.kind}:${citation.ref}`}>
            <span className="ai-panel__citation-ref">{citation.ref}</span>
            {citation.quote ? (
              <span className="ai-panel__citation-quote">“{citation.quote}”</span>
            ) : null}
          </li>
        ))}
      </ul>
      {modelVersion ? (
        <p className="ai-panel__citation-ref" style={{ marginBottom: 0 }}>
          {modelVersion}
        </p>
      ) : null}
    </section>
  );
}

/**
 * The counterweight. Deterministic facts get a plain surface and a quiet label, so the two
 * kinds of content are distinguishable *side by side* rather than only in isolation.
 */
export function FactPanel({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section className="fact-panel" data-kind="fact" data-derivation="deterministic">
      <p className="fact-panel__label">{label}</p>
      {children}
    </section>
  );
}
