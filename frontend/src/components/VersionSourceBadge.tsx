import { Badge } from './Badge';
import { VERSION_SOURCE_TREATMENTS, tone } from './treatments';
import type { VersionSource } from '../types/api';

/**
 * How a version was established — the evidence behind the confidence badge.
 *
 * `package_manager` and `vendor_api` are the device or its manufacturer stating what is
 * installed. `banner` is a service advertising a string, which a backported fix leaves
 * unchanged for years. That difference is why `probable` exists, and showing the *source*
 * beside the confidence lets an analyst see the reasoning rather than trust the label
 * (AGENTS.md §3).
 */
export function VersionSourceBadge({ source }: { source: VersionSource }) {
  const treatment = VERSION_SOURCE_TREATMENTS[source];
  return (
    <Badge
      kind="version-source"
      variant={source}
      tone={tone(treatment.tokens)}
      mark={treatment.mark}
      title={treatment.title}
    >
      {treatment.label}
    </Badge>
  );
}
