import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  CONFIDENCE_TREATMENTS,
  MANAGEMENT_TREATMENTS,
  PRIORITY_TREATMENTS,
  REVIEW_TREATMENTS,
  VERSION_SOURCE_TREATMENTS,
  tone,
} from '../components';
import { CONFIDENCE_STATES, MANAGEMENT_STATES, PRIORITIES, VERSION_SOURCES } from '../types/api';

/**
 * The two properties that keep the language a language.
 *
 * **One source for the colours.** A component that hardcodes `#dc2626` has forked the visual
 * system, and the fork will not be noticed until two screens disagree in front of a customer.
 * This test reads the component sources the way the backend's boundary tests read Python: it
 * fails on a literal colour, so the tokens stay the only place a colour is chosen.
 *
 * **One source for the variants.** Each distinction is a `Record<Union, Treatment>` keyed by
 * the API's own union, so a state added to the backend is a compile error rather than an
 * unstyled badge. These tests assert the other direction too — that no treatment exists for a
 * state the contract does not have — because a stale entry is how a system starts rendering
 * things nobody sends any more.
 */

const COMPONENT_DIR = join(import.meta.dirname, '..', 'components');
const TOKENS_CSS = readFileSync(join(import.meta.dirname, 'tokens.css'), 'utf8');

const componentFiles = readdirSync(COMPONENT_DIR).filter(
  (name) =>
    (name.endsWith('.tsx') || name.endsWith('.css') || name.endsWith('.ts')) &&
    !name.includes('.test.'),
);

const sourceOf = (name: string) => readFileSync(join(COMPONENT_DIR, name), 'utf8');

/** Hex, rgb()/rgba(), hsl() — every way a colour gets written by hand. */
const LITERAL_COLOUR = /#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/gi;

describe('the theme is the single source of the visual language', () => {
  it('finds the components to check', () => {
    expect(componentFiles.length).toBeGreaterThan(5);
  });

  it.each(componentFiles)('%s contains no literal colour', (name) => {
    const matches = sourceOf(name).match(LITERAL_COLOUR) ?? [];

    expect(matches).toEqual([]);
  });

  it('defines every token the components reference', () => {
    // A `var(--thing)` that resolves to nothing renders as an unstyled element — visible in
    // the gallery, invisible in a unit test, and easy to ship.
    const referenced = new Set<string>();
    for (const name of componentFiles) {
      for (const match of sourceOf(name).matchAll(/var\(--([a-z0-9-]+)/g)) {
        referenced.add(match[1] as string);
      }
    }
    // Tokens the component system sets for itself, rather than reads from the theme.
    const locallyDefined = new Set(['badge-fg', 'badge-bg', 'badge-border']);

    const missing = [...referenced].filter(
      (token) => !locallyDefined.has(token) && !TOKENS_CSS.includes(`--${token}:`),
    );

    expect(missing).toEqual([]);
  });

  it('builds tones from token names rather than colours', () => {
    // `tone('confidence-probable')` names a meaning; a hex names a pixel. The former survives
    // a redesign, and more importantly it survives a *second* screen.
    const treatments = sourceOf('treatments.ts');

    expect(treatments).toContain('var(--${prefix}-fg)');
    expect(tone('confidence-probable')).toEqual({
      fg: 'var(--confidence-probable-fg)',
      bg: 'var(--confidence-probable-bg)',
      border: 'var(--confidence-probable-border)',
    });
  });
});

describe('the distinctions are driven by the API contract', () => {
  it('has exactly one confidence treatment per contract state', () => {
    expect(Object.keys(CONFIDENCE_TREATMENTS).sort()).toEqual([...CONFIDENCE_STATES].sort());
  });

  it('has exactly one management treatment per contract state', () => {
    expect(Object.keys(MANAGEMENT_TREATMENTS).sort()).toEqual([...MANAGEMENT_STATES].sort());
  });

  it('has exactly one version-source treatment per contract state', () => {
    expect(Object.keys(VERSION_SOURCE_TREATMENTS).sort()).toEqual([...VERSION_SOURCES].sort());
  });

  it('defines a priority token trio for every band', () => {
    for (const priority of PRIORITIES) {
      expect(TOKENS_CSS).toContain(`--priority-${priority}-fg:`);
      expect(TOKENS_CSS).toContain(`--priority-${priority}-bg:`);
      expect(TOKENS_CSS).toContain(`--priority-${priority}-border:`);
    }
  });

  it('resolves each treatment to tokens that exist', () => {
    const treatments = [
      ...Object.values(CONFIDENCE_TREATMENTS),
      ...Object.values(MANAGEMENT_TREATMENTS),
      ...Object.values(VERSION_SOURCE_TREATMENTS),
      ...Object.values(REVIEW_TREATMENTS),
      ...Object.values(PRIORITY_TREATMENTS),
    ];

    for (const treatment of treatments) {
      expect(TOKENS_CSS).toContain(`--${treatment.tokens}-fg:`);
      expect(TOKENS_CSS).toContain(`--${treatment.tokens}-bg:`);
      expect(TOKENS_CSS).toContain(`--${treatment.tokens}-border:`);
    }
  });

  it('gives every distinction its own hue rather than sharing one', () => {
    // Shadow IT and a KEV finding must not read as the same kind of thing, and neither may
    // be confusable with AI output. Checked at the token layer, where the choice is made.
    const shadow = TOKENS_CSS.match(/--management-shadow-fg:\s*var\(--([a-z0-9-]+)\)/)?.[1];
    const ai = TOKENS_CSS.match(/--ai-fg:\s*var\(--([a-z0-9-]+)\)/)?.[1];

    expect(shadow).toBeDefined();
    expect(ai).toBeDefined();
    expect(ai).not.toEqual(shadow);
  });
});
