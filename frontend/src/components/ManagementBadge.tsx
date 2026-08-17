import { Badge } from './Badge';
import { MANAGEMENT_TREATMENTS, tone } from './treatments';
import type { ManagementState } from '../types/api';

/**
 * **Distinction 2 of 3: does anything in the estate manage this device?**
 *
 * `unmanaged` is the product's headline — a device on the network that no IAM, MDM or CMDB
 * knows about — and the one management state with real colour.
 *
 * `unknown` is the one that has to stay boring. It means the reconciliation could not
 * confidently match this asset to a managed record, and the backend refuses to count it as
 * shadow IT (ADR-0009). The interface refuses just as hard: the label is "Unknown", never
 * "Possibly shadow IT", because an ambiguous match rendered in red is the same overclaim made
 * visually instead of numerically.
 */
export function ManagementBadge({ state }: { state: ManagementState }) {
  const treatment = MANAGEMENT_TREATMENTS[state];
  return (
    <Badge kind="management" variant={state} tone={tone(treatment.tokens)} title={treatment.title}>
      {treatment.label}
    </Badge>
  );
}
