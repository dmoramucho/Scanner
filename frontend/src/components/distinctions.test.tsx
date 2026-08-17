import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  AiPanel,
  ConfidenceBadge,
  FactPanel,
  InferredValue,
  KevBadge,
  ManagementBadge,
  PriorityBadge,
  ReviewStateBadge,
  VersionSourceBadge,
} from './index';
import { CONFIDENCE_STATES, MANAGEMENT_STATES, PRIORITIES, VERSION_SOURCES } from '../types/api';
import { CITATIONS, INFERRED_VLAN, RATIONALE } from '../mock/fixtures';

/**
 * The component system's tests.
 *
 * They assert the property the whole layer exists for: **the three distinctions are visually
 * distinguishable, consistently, in every state**. Consistency is checked structurally — each
 * component publishes `data-kind` and `data-variant`, and the treatment comes from a token
 * name rather than a colour — so a test can prove two states differ without asserting on a hex
 * value that a redesign would legitimately change (m4-design §3).
 */

const styleOf = (element: HTMLElement) => element.getAttribute('style') ?? '';

describe('distinction 1: confidence', () => {
  it.each(CONFIDENCE_STATES)('renders %s with its own treatment', (state) => {
    render(<ConfidenceBadge state={state} />);

    const badge = screen.getByText(/confirmed|probable|verified/i);
    expect(badge).toHaveAttribute('data-kind', 'confidence');
    expect(badge).toHaveAttribute('data-variant', state);
  });

  it('gives every state a distinct treatment', () => {
    const treatments = CONFIDENCE_STATES.map((state) => {
      const { container } = render(<ConfidenceBadge state={state} />);
      return styleOf(container.querySelector('.badge') as HTMLElement);
    });

    expect(new Set(treatments).size).toBe(CONFIDENCE_STATES.length);
  });

  it('does not dress probable as an alarm', () => {
    // The rule from ux-design §2: probable is a work queue, not an alert. It must not share
    // the treatment of the state reserved for demonstrated exploitability.
    const { container: probable } = render(<ConfidenceBadge state="probable" />);
    const { container: verified } = render(<ConfidenceBadge state="verified_exploitable" />);

    expect(styleOf(probable.querySelector('.badge') as HTMLElement)).not.toEqual(
      styleOf(verified.querySelector('.badge') as HTMLElement),
    );
  });

  it('says what probable means, because the label alone is a trap', () => {
    render(<ConfidenceBadge state="probable" />);

    expect(screen.getByText('Probable')).toHaveAttribute(
      'title',
      expect.stringContaining('backported'),
    );
  });
});

describe('distinction 2: management state', () => {
  it.each(MANAGEMENT_STATES)('renders %s with its own treatment', (state) => {
    const { container } = render(<ManagementBadge state={state} />);

    const badge = container.querySelector('.badge');
    expect(badge).toHaveAttribute('data-kind', 'management');
    expect(badge).toHaveAttribute('data-variant', state);
  });

  it('never dresses unknown as shadow IT', () => {
    // The overclaim ADR-0009 refuses numerically, refused visually. An ambiguous match is
    // grey and says "Unknown"; only a real unmanaged asset carries the shadow-IT treatment.
    const { container: unknown } = render(<ManagementBadge state="unknown" />);
    const { container: shadow } = render(<ManagementBadge state="unmanaged" />);

    expect(within(unknown).getByText('Unknown')).toBeInTheDocument();
    expect(within(unknown).queryByText(/shadow/i)).not.toBeInTheDocument();
    expect(within(shadow).getByText('Shadow IT')).toBeInTheDocument();
    expect(styleOf(unknown.querySelector('.badge') as HTMLElement)).not.toEqual(
      styleOf(shadow.querySelector('.badge') as HTMLElement),
    );
  });

  it('explains that unknown is not a finding', () => {
    render(<ManagementBadge state="unknown" />);

    expect(screen.getByText('Unknown')).toHaveAttribute(
      'title',
      expect.stringContaining('not counted as shadow IT'),
    );
  });
});

describe('distinction 3: fact vs AI', () => {
  it('marks AI content as AI, with its citations, confidence and review state', () => {
    render(
      <AiPanel
        recommendation="raise_priority"
        confidence={0.82}
        state="proposed"
        citations={CITATIONS}
      >
        {RATIONALE}
      </AiPanel>,
    );

    expect(screen.getByText('AI-generated')).toBeInTheDocument();
    expect(screen.getByText('Raise priority')).toBeInTheDocument();
    expect(screen.getByText(/Model confidence 82%/)).toBeInTheDocument();
    expect(screen.getByText('Awaiting review')).toBeInTheDocument();
    // The citations are the trust mechanism, not decoration (ux-design §3.4).
    expect(screen.getByText('CVE-2023-25690')).toBeInTheDocument();
    expect(screen.getByText(/allow a HTTP Request Smuggling attack/)).toBeInTheDocument();
  });

  it('is structurally distinct from a deterministic fact panel', () => {
    const { container } = render(
      <>
        <FactPanel label="Deterministic match">the match</FactPanel>
        <AiPanel recommendation="maintain" confidence={0.5} state="proposed" citations={CITATIONS}>
          the insight
        </AiPanel>
      </>,
    );

    const fact = container.querySelector('[data-kind="fact"]');
    const ai = container.querySelector('[data-kind="ai"]');
    expect(fact).toHaveAttribute('data-derivation', 'deterministic');
    expect(ai).toHaveAttribute('data-derivation', 'llm_generated');
    expect(fact?.className).not.toEqual(ai?.className);
  });

  it('shows the KEV lock on an insight that cannot bury its finding', () => {
    render(
      <AiPanel
        recommendation="maintain"
        confidence={0.6}
        state="proposed"
        citations={CITATIONS}
        kevLocked
      >
        the insight
      </AiPanel>,
    );

    expect(screen.getByText('KEV locked visible')).toBeInTheDocument();
  });

  it.each(['proposed', 'human_reviewed', 'accepted'] as const)(
    'distinguishes review state %s',
    (state) => {
      const { container } = render(<ReviewStateBadge state={state} />);

      expect(container.querySelector('.badge')).toHaveAttribute('data-variant', state);
    },
  );
});

describe('the recurring signals', () => {
  it('renders KEV as urgent and locked', () => {
    const { container } = render(<KevBadge />);

    const badge = container.querySelector('.badge');
    expect(badge).toHaveClass('badge--loud');
    expect(badge).toHaveAttribute('data-kind', 'kev');
    expect(screen.getByText('KEV')).toBeInTheDocument();
    expect(badge?.getAttribute('title')).toContain('no recommendation can hide it');
  });

  it('is the only badge with the loud treatment', () => {
    // If everything shouts, nothing is urgent (ux-design §2). Asserted across the system.
    const { container } = render(
      <>
        <KevBadge />
        <ConfidenceBadge state="verified_exploitable" />
        <ManagementBadge state="unmanaged" />
        <PriorityBadge priority="p1" reason="because" />
      </>,
    );

    expect(container.querySelectorAll('.badge--loud')).toHaveLength(1);
  });

  it.each(PRIORITIES)('renders band %s with the reason that produced it', (priority) => {
    const reason = `CISA lists CVE-2023-25690 as known exploited (${priority}).`;
    const { container } = render(
      <PriorityBadge priority={priority} reason={reason} rule="kev-actively-exploited" />,
    );

    const badge = container.querySelector('[data-kind="priority"]');
    expect(badge).toHaveAttribute('data-variant', priority);
    // The reason is never separated from the band — it is one hover away, always.
    expect(badge?.getAttribute('title')).toContain(reason);
    expect(badge?.getAttribute('title')).toContain('kev-actively-exploited');
  });

  it('can show the reason inline where there is room', () => {
    render(<PriorityBadge priority="p1" reason="CISA lists it as known exploited." showReason />);

    expect(screen.getByTestId('priority-reason')).toHaveTextContent('known exploited');
  });

  it.each(VERSION_SOURCES)('distinguishes version source %s', (source) => {
    const { container } = render(<VersionSourceBadge source={source} />);

    expect(container.querySelector('.badge')).toHaveAttribute('data-variant', source);
  });

  it('separates a credentialed read from a banner', () => {
    const { container: credentialed } = render(<VersionSourceBadge source="package_manager" />);
    const { container: banner } = render(<VersionSourceBadge source="banner" />);

    expect(within(credentialed).getByText('Credentialed')).toBeInTheDocument();
    expect(within(banner).getByText('Banner')).toBeInTheDocument();
    expect(styleOf(credentialed.querySelector('.badge') as HTMLElement)).not.toEqual(
      styleOf(banner.querySelector('.badge') as HTMLElement),
    );
    expect(banner.querySelector('.badge')?.getAttribute('title')).toContain('false positive');
  });

  it('marks an inferred VLAN as inferred', () => {
    const { container } = render(<InferredValue value={INFERRED_VLAN} label="VLAN" />);

    const badge = container.querySelector('.badge');
    expect(badge).toHaveAttribute('data-variant', 'inferred');
    expect(screen.getByText('VLAN 60 (IoT)')).toBeInTheDocument();
    expect(screen.getByText('inferred')).toBeInTheDocument();
    expect(badge?.getAttribute('title')).toContain('not measured');
  });

  it('renders an unmapped address as unknown rather than a guess', () => {
    render(<InferredValue value={null} label="VLAN" />);

    expect(screen.getByText('VLAN unknown')).toBeInTheDocument();
    expect(screen.queryByText(/VLAN \d+/)).not.toBeInTheDocument();
  });

  it('cannot be told to hide the inferred marker', () => {
    // There is no prop for it. The backend carries `inferred` precisely because a UI might
    // otherwise present a derivation as a measurement (ADR-0015), so the marker is not
    // configurable — this asserts the API surface, which is where that rule lives.
    const props = Object.keys(
      InferredValue({ value: INFERRED_VLAN, label: 'VLAN' }).props as Record<string, unknown>,
    );

    expect(props).not.toContain('hideInferred');
  });
});
