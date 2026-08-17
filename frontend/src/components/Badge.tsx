import type { ReactNode } from 'react';
import './Badge.css';

/**
 * The shape every distinction is drawn with.
 *
 * A badge takes its colours from CSS custom properties supplied by the caller — never from a
 * variant list of its own. That inversion is the whole point of the component system: the
 * *meaning* of a colour is defined once in `tokens.css`, and this component knows only how a
 * badge is shaped. A new signal is a token triple and a wrapper, not an edit here
 * (m4-design §3).
 */
export interface BadgeProps {
  /** The token trio that carries the meaning: `--confidence-probable-*`, and so on. */
  tone: { fg: string; bg: string; border: string };
  /** A leading glyph, for signals that carry one (the KEV lock). */
  mark?: string | undefined;
  /** Secondary text inside the badge, de-emphasised — a score, a version. */
  detail?: string | undefined;
  /** The full explanation, shown on hover and to assistive technology. */
  title?: string | undefined;
  /** Solid treatment. Reserved for KEV. */
  loud?: boolean;
  /** The machine-readable variant, so tests and CSS can target it without reading text. */
  variant: string;
  /** What kind of distinction this is — `confidence`, `management`, `priority`, … */
  kind: string;
  children: ReactNode;
}

export function Badge({
  tone,
  mark,
  detail,
  title,
  loud = false,
  variant,
  kind,
  children,
}: BadgeProps) {
  return (
    <span
      className={loud ? 'badge badge--loud' : 'badge'}
      data-kind={kind}
      data-variant={variant}
      title={title}
      style={
        {
          '--badge-fg': tone.fg,
          '--badge-bg': tone.bg,
          '--badge-border': tone.border,
        } as React.CSSProperties
      }
    >
      {mark ? (
        <span className="badge__mark" aria-hidden="true">
          {mark}
        </span>
      ) : null}
      {children}
      {detail ? <span className="badge__detail">{detail}</span> : null}
    </span>
  );
}
