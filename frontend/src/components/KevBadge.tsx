import { Badge } from './Badge';
import { tone } from './treatments';

/**
 * KEV: the one signal allowed to shout.
 *
 * CISA lists this CVE as being exploited in the wild *right now*. It is solid rather than
 * tinted — the only badge in the system that is — because everything else in the palette is
 * quiet, and if this does not stand out at a glance the hierarchy has failed (ux-design §2).
 *
 * The lock is not decoration. A KEV finding cannot be lowered below its floor by the model, by
 * the analyst, or by a request that skips the UI entirely (ADR-0015, ADR-0017). The badge says
 * so, so a disabled control elsewhere reads as a rule rather than as a bug.
 */
export function KevBadge({ locked = true }: { locked?: boolean }) {
  return (
    <Badge
      kind="kev"
      variant="kev"
      tone={tone('signal-kev')}
      mark={locked ? '🔒' : undefined}
      loud
      title={
        'CISA lists this CVE as known exploited. ' +
        (locked ? 'It stays visible: no recommendation can hide it.' : '')
      }
    >
      KEV
    </Badge>
  );
}
