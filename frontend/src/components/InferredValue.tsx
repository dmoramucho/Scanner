import { Badge } from './Badge';
import { tone } from './treatments';
import type { ObservedValue } from '../types/api';

/**
 * A value the backend derived rather than measured — today, the VLAN label.
 *
 * There is no switch to ask, so a segment label comes from the operator's subnet map: it
 * describes how the network was *designed*, and a device with a static address from another
 * range makes it wrong without anything looking wrong (ADR-0015). The API sends
 * `inferred: true` and a confidence below 1.0 precisely so this component can refuse to render
 * it as ground truth.
 *
 * The rule this component encodes: **if `inferred` is true, the marker is not optional.** A
 * caller cannot pass a flag to hide it, because the whole reason the backend carries the field
 * is that a UI might otherwise present a guess as a fact.
 *
 * A `null` value renders as *Unknown* — never a plausible-looking VLAN. "We don't know" is an
 * answer the backend takes seriously and so does this.
 */
export interface InferredValueProps {
  value: ObservedValue | null;
  /** What this is a value *of* — "VLAN", "Segment". Shown when there is nothing to show. */
  label: string;
}

export function InferredValue({ value, label }: InferredValueProps) {
  if (value === null) {
    return (
      <Badge
        kind="inferred-value"
        variant="unknown"
        tone={tone('management-unknown')}
        title={`No mapped range contains this asset's address, so its ${label.toLowerCase()} is unknown. Not guessed.`}
      >
        {`${label} unknown`}
      </Badge>
    );
  }

  return (
    <Badge
      kind="inferred-value"
      variant={value.inferred ? 'inferred' : 'measured'}
      tone={tone(value.inferred ? 'inferred' : 'source-ground-truth')}
      mark={value.inferred ? '≈' : undefined}
      detail={value.inferred ? 'inferred' : undefined}
      title={
        value.inferred
          ? `Derived from the operator's subnet map (${value.provenance.source}), not measured. ` +
            `Confidence ${(value.provenance.confidence * 100).toFixed(0)}%.`
          : `Observed by ${value.provenance.source}.`
      }
    >
      {value.value}
    </Badge>
  );
}
