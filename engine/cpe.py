"""CPE parsing and version-range comparison.

The correctness floor of the whole vulnerability path. A CVE matched to a version it does
not affect is a false positive that discredits the tool; a CVE *not* matched to a version it
does affect is a security hole we created (AGENTS.md §4.9). Both are decided here, in
about a hundred lines of comparison logic, which is why this is a separate module with its
own tests rather than a helper inside the correlator.

**The feed proposes; this module disposes.** NVD's `cpeName` query already does server-side
matching, and it is broad — it will return CVEs for a product regardless of whether our
particular version is in the affected range. Trusting that would be trusting a remote
service's version arithmetic. So every criterion NVD returns is re-checked locally against
the component's actual version, and only the ones that genuinely apply become matches.

**Version comparison is deliberately hand-written.** Software versions in CPE space are not
PEP 440, not semver, and not consistent: `2.4.52`, `8.9p1`, `3.0.2-0ubuntu1.18`, `1.0.0rc2`.
The comparison below tokenises into numeric and non-numeric runs and compares run by run —
the same "natural ordering" every CPE matcher converges on — and, crucially, **says when it
does not know**. An inconclusive comparison is a first-class result, not a guess in either
direction (ADR-0012).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

#: CPE 2.3 formatted-string components, in order.
_CPE_FIELDS: Final = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)

#: A CPE field that means "any" or "not applicable" — neither is a concrete version.
_WILDCARDS: Final = frozenset({"*", "-", ""})

_TOKEN = re.compile(r"(\d+|[a-z]+)")

#: Non-numeric suffixes that mark a *pre*-release: `1.0.0rc2` precedes `1.0.0`. Anything
#: else non-numeric (`8.9p1`, `2.4.52ubuntu1`) is a patch level and *follows* the bare
#: version, which is the opposite direction and the reason this list is explicit.
_PRERELEASE_MARKERS: Final = frozenset({"alpha", "a", "beta", "b", "rc", "pre", "dev", "snapshot"})


class VersionOrder(StrEnum):
    """The result of comparing two versions, including the honest third answer."""

    LESS = "less"
    EQUAL = "equal"
    GREATER = "greater"
    UNKNOWN = "unknown"  # one side is not a comparable version string


@dataclass(frozen=True, slots=True)
class Cpe:
    """A parsed CPE 2.3 formatted string.

    Only the fields correlation actually reasons about are named; the rest are kept so a
    criterion can be compared field by field without pretending the others do not exist.
    """

    part: str
    vendor: str
    product: str
    version: str
    fields: tuple[str, ...]

    @property
    def identity(self) -> tuple[str, str, str]:
        """What makes two CPEs the same *product*, ignoring version."""
        return (self.part, self.vendor, self.product)

    @property
    def has_concrete_version(self) -> bool:
        return self.version not in _WILDCARDS


def parse_cpe(value: str) -> Cpe | None:
    """Parse a CPE 2.3 formatted string, or return None.

    Returns rather than raises: a malformed criterion in a feed record is a record we skip,
    not a run we abort (AGENTS.md §2.9).
    """
    text = value.strip()
    if not text.lower().startswith("cpe:2.3:"):
        return None

    # `\:` is an escaped colon inside a field (`cpe:2.3:a:vendor:pro\:duct:…`), so the split
    # cannot be naive.
    parts = re.split(r"(?<!\\):", text)
    if len(parts) < 6:  # "cpe", "2.3", part, vendor, product, version at minimum
        return None

    fields = [field.replace("\\:", ":").lower() for field in parts[2:]]
    fields.extend([""] * (len(_CPE_FIELDS) - len(fields)))

    return Cpe(
        part=fields[0],
        vendor=fields[1],
        product=fields[2],
        version=fields[3],
        fields=tuple(fields[: len(_CPE_FIELDS)]),
    )


def _tokenize(version: str) -> list[str] | None:
    """Split a version into comparable runs, or None if there is nothing to compare.

    `2.4.52` → `["2", "4", "52"]`; `8.9p1` → `["8", "9", "p", "1"]`;
    `3.0.2-0ubuntu1.18` → `["3", "0", "2", "0", "ubuntu", "1", "18"]`.
    """
    normalized = version.strip().lower()
    if normalized in _WILDCARDS:
        return None
    tokens = _TOKEN.findall(normalized)
    if not tokens or not any(token.isdigit() for token in tokens):
        # No numeric component at all ("unknown", "latest", "n/a"): not a version we can
        # place on a line.
        return None
    return tokens


def compare_versions(left: str, right: str) -> VersionOrder:
    """Order two version strings, or admit that we cannot.

    Numeric runs compare numerically (so `10` follows `9`, which a lexical compare gets
    wrong); a numeric run outranks an alphabetic one at the same position, *except* for the
    documented pre-release markers, where the alphabetic side sorts first. When one side
    cannot be tokenised at all, the answer is `UNKNOWN` — never a coin flip, because a
    guess here becomes either a false positive or a hidden vulnerability.
    """
    left_tokens = _tokenize(left)
    right_tokens = _tokenize(right)
    if left_tokens is None or right_tokens is None:
        return VersionOrder.UNKNOWN

    for index in range(max(len(left_tokens), len(right_tokens))):
        left_token = left_tokens[index] if index < len(left_tokens) else None
        right_token = right_tokens[index] if index < len(right_tokens) else None

        if left_token is None or right_token is None:
            # One version ran out. `1.0` vs `1.0.1` → shorter is smaller, unless what
            # follows marks a pre-release: `1.0` vs `1.0rc1` → the rc is *earlier*.
            remainder = right_tokens[index:] if left_token is None else left_tokens[index:]
            shorter_is_greater = bool(remainder) and remainder[0] in _PRERELEASE_MARKERS
            if left_token is None:
                return VersionOrder.GREATER if shorter_is_greater else VersionOrder.LESS
            return VersionOrder.LESS if shorter_is_greater else VersionOrder.GREATER

        if left_token == right_token:
            continue

        left_numeric, right_numeric = left_token.isdigit(), right_token.isdigit()
        if left_numeric and right_numeric:
            return VersionOrder.LESS if int(left_token) < int(right_token) else VersionOrder.GREATER
        if left_numeric != right_numeric:
            # A number beats a word at the same position — `1.0.1` follows `1.0.rc` — unless
            # the word is a pre-release marker, which is exactly what those markers mean.
            word = right_token if left_numeric else left_token
            word_is_earlier = word in _PRERELEASE_MARKERS
            if left_numeric:
                return VersionOrder.GREATER if word_is_earlier else VersionOrder.LESS
            return VersionOrder.LESS if word_is_earlier else VersionOrder.GREATER

        return VersionOrder.LESS if left_token < right_token else VersionOrder.GREATER

    return VersionOrder.EQUAL


class RangeVerdict(StrEnum):
    """Whether a version falls in a CVE's affected range."""

    IN_RANGE = "in_range"
    OUT_OF_RANGE = "out_of_range"
    #: We could not decide — an unparseable version on either side. Reported rather than
    #: resolved: guessing "in" invents a finding, guessing "out" hides one.
    INCONCLUSIVE = "inconclusive"


def version_in_range(
    version: str | None,
    *,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
) -> RangeVerdict:
    """Is this version inside the affected range?

    An absent bound is unbounded on that side, which is what NVD means by omitting it. A
    range with no bounds at all matches every version of the product — also what NVD means,
    and it does publish such entries.

    The boundary semantics are exactly NVD's, and they are the thing to get right: an
    *including* bound is closed and an *excluding* bound is open, so `versionEndExcluding:
    2.4.58` means 2.4.57 is affected and 2.4.58 is not.
    """
    if version is None or _tokenize(version) is None:
        # No usable version on our side. If the CVE affects every version of the product,
        # that is still a decision we can make; otherwise we genuinely cannot tell.
        unbounded = not any((start_including, start_excluding, end_including, end_excluding))
        return RangeVerdict.IN_RANGE if unbounded else RangeVerdict.INCONCLUSIVE

    checks = (
        (start_including, (VersionOrder.GREATER, VersionOrder.EQUAL)),
        (start_excluding, (VersionOrder.GREATER,)),
        (end_including, (VersionOrder.LESS, VersionOrder.EQUAL)),
        (end_excluding, (VersionOrder.LESS,)),
    )

    for bound, accepted in checks:
        if not bound:
            continue
        order = compare_versions(version, bound)
        if order is VersionOrder.UNKNOWN:
            return RangeVerdict.INCONCLUSIVE
        if order not in accepted:
            return RangeVerdict.OUT_OF_RANGE

    return RangeVerdict.IN_RANGE
