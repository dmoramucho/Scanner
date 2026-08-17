import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Gallery } from './Gallery';
import { CONFIDENCE_STATES, MANAGEMENT_STATES, PRIORITIES, VERSION_SOURCES } from '../types/api';

/**
 * The gallery is the consistency check made visible, so it is also a test: every state of
 * every distinction has to appear on it. A component added without a gallery entry is a
 * component nobody will compare against the others, which is how a language drifts.
 */
describe('the component gallery', () => {
  it('renders every confidence state', () => {
    const { container } = render(<Gallery />);

    for (const state of CONFIDENCE_STATES) {
      expect(
        container.querySelector(`[data-kind="confidence"][data-variant="${state}"]`),
      ).not.toBeNull();
    }
  });

  it('renders every management state', () => {
    const { container } = render(<Gallery />);

    for (const state of MANAGEMENT_STATES) {
      expect(
        container.querySelector(`[data-kind="management"][data-variant="${state}"]`),
      ).not.toBeNull();
    }
  });

  it('renders every priority band and every version source', () => {
    const { container } = render(<Gallery />);

    for (const priority of PRIORITIES) {
      expect(
        container.querySelector(`[data-kind="priority"][data-variant="${priority}"]`),
      ).not.toBeNull();
    }
    for (const source of VERSION_SOURCES) {
      expect(
        container.querySelector(`[data-kind="version-source"][data-variant="${source}"]`),
      ).not.toBeNull();
    }
  });

  it('shows a fact panel and an AI panel side by side', () => {
    // The distinction is only convincing when the two are adjacent — in isolation, any
    // treatment looks deliberate (ux-design §2).
    const { container } = render(<Gallery />);

    expect(container.querySelector('[data-kind="fact"]')).not.toBeNull();
    expect(container.querySelector('[data-kind="ai"]')).not.toBeNull();
  });

  it('shows an inferred VLAN and an unknown one', () => {
    render(<Gallery />);

    expect(screen.getByText('VLAN 60 (IoT)')).toBeInTheDocument();
    expect(screen.getByText('VLAN unknown')).toBeInTheDocument();
  });

  it('renders the worklist rows from typed fixtures', () => {
    render(<Gallery />);

    expect(screen.getByText('cam-lobby-01')).toBeInTheDocument();
    expect(screen.getByText('app-server-02')).toBeInTheDocument();
    expect(screen.getByText('printer-3f')).toBeInTheDocument();
  });
});
