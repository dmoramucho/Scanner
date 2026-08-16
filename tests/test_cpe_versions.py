"""Version comparison and CPE parsing, on their own.

Separated from the correlator because this is where the correctness of every vulnerability
finding actually lives, and because the failure modes are arithmetic rather than
architectural: `2.4.10` must follow `2.4.9`, and `2.4.6` must precede `2.4.57`. A lexical
comparison — the obvious wrong implementation — gets both backwards (ADR-0012).
"""

from __future__ import annotations

import pytest

from engine.cpe import RangeVerdict, VersionOrder, compare_versions, parse_cpe, version_in_range

# ------------------------------------------------------------------- CPE parsing


def test_a_cpe_parses_into_its_identity_fields() -> None:
    cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*")

    assert cpe is not None
    assert cpe.identity == ("a", "apache", "http_server")
    assert cpe.version == "2.4.52"
    assert cpe.has_concrete_version is True


@pytest.mark.parametrize("wildcard", ["*", "-"])
def test_a_wildcarded_version_is_not_concrete(wildcard: str) -> None:
    cpe = parse_cpe(f"cpe:2.3:a:apache:http_server:{wildcard}:*:*:*:*:*:*:*")

    assert cpe is not None
    assert cpe.has_concrete_version is False


def test_cpe_comparison_is_case_insensitive() -> None:
    upper = parse_cpe("cpe:2.3:a:Apache:HTTP_Server:2.4.52:*:*:*:*:*:*:*")
    lower = parse_cpe("cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*")

    assert upper is not None
    assert lower is not None
    assert upper.identity == lower.identity


def test_an_escaped_colon_inside_a_field_survives_parsing() -> None:
    """CPE escapes a literal colon as `\\:`, so splitting naively would shift every field
    after it — silently turning one product into another."""
    cpe = parse_cpe(r"cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*")

    assert cpe is not None
    assert cpe.product == "pro:duct"
    assert cpe.version == "1.0"


@pytest.mark.parametrize("junk", ["", "not-a-cpe", "cpe:/a:apache:http_server", "cpe:2.3:a:x"])
def test_a_malformed_cpe_returns_none_rather_than_raising(junk: str) -> None:
    """A malformed criterion in a feed record is a record we skip, not a run we abort."""
    assert parse_cpe(junk) is None


# ------------------------------------------------------------ version comparison


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("2.4.52", "2.4.52", VersionOrder.EQUAL),
        ("2.4.52", "2.4.53", VersionOrder.LESS),
        ("2.4.53", "2.4.52", VersionOrder.GREATER),
        # The two a lexical compare gets wrong, which is the whole reason for this module.
        ("2.4.10", "2.4.9", VersionOrder.GREATER),
        ("2.4.6", "2.4.57", VersionOrder.LESS),
        # Differing lengths.
        ("2.4", "2.4.1", VersionOrder.LESS),
        ("2.4.1", "2.4", VersionOrder.GREATER),
        ("2.4.0", "2.4", VersionOrder.GREATER),
        # Distribution suffixes: a patched build follows the bare version.
        ("3.0.2-0ubuntu1.18", "3.0.2", VersionOrder.GREATER),
        ("8.9p1", "8.9", VersionOrder.GREATER),
        ("8.9p1", "8.9p2", VersionOrder.LESS),
        # Pre-releases precede the release they lead up to.
        ("1.0.0rc2", "1.0.0", VersionOrder.LESS),
        ("1.0.0-beta", "1.0.0", VersionOrder.LESS),
        ("1.0.0rc1", "1.0.0rc2", VersionOrder.LESS),
    ],
)
def test_versions_order_the_way_a_person_would_expect(
    left: str, right: str, expected: VersionOrder
) -> None:
    assert compare_versions(left, right) is expected


@pytest.mark.parametrize(
    ("left", "right"),
    [("unknown", "2.4.52"), ("2.4.52", "latest"), ("", "1.0"), ("n/a", "n/a"), ("*", "1.0")],
)
def test_an_uncomparable_version_says_so_rather_than_guessing(left: str, right: str) -> None:
    """`UNKNOWN` is a first-class answer. A guess here becomes either a false positive or a
    hidden vulnerability, and neither is ours to invent (AGENTS.md §4.9)."""
    assert compare_versions(left, right) is VersionOrder.UNKNOWN


def test_comparison_is_antisymmetric() -> None:
    """If a < b then b > a, for every pair above. A comparison that is not antisymmetric
    would put a version inside a range from one side and outside it from the other."""
    pairs = [("2.4.9", "2.4.10"), ("1.0", "1.0.1"), ("1.0.0rc1", "1.0.0"), ("8.9", "8.9p1")]

    for left, right in pairs:
        forward = compare_versions(left, right)
        backward = compare_versions(right, left)
        assert forward is VersionOrder.LESS
        assert backward is VersionOrder.GREATER


# ----------------------------------------------------------------- range checks


def test_an_unbounded_range_covers_every_version() -> None:
    """NVD publishes criteria with no bounds, and it means the whole product is affected."""
    assert version_in_range("1.0") is RangeVerdict.IN_RANGE
    assert version_in_range("99.99.99") is RangeVerdict.IN_RANGE


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("2.3.99", RangeVerdict.OUT_OF_RANGE),
        ("2.4.0", RangeVerdict.IN_RANGE),  # start is *including*
        ("2.4.57", RangeVerdict.IN_RANGE),
        ("2.4.58", RangeVerdict.OUT_OF_RANGE),  # end is *excluding*
    ],
)
def test_the_boundary_semantics_are_exactly_nvds(version: str, expected: RangeVerdict) -> None:
    verdict = version_in_range(version, start_including="2.4.0", end_excluding="2.4.58")

    assert verdict is expected


def test_an_excluding_start_and_including_end_are_the_mirror_image() -> None:
    assert version_in_range("2.4.0", start_excluding="2.4.0") is RangeVerdict.OUT_OF_RANGE
    assert version_in_range("2.4.1", start_excluding="2.4.0") is RangeVerdict.IN_RANGE
    assert version_in_range("2.4.58", end_including="2.4.58") is RangeVerdict.IN_RANGE
    assert version_in_range("2.4.59", end_including="2.4.58") is RangeVerdict.OUT_OF_RANGE


def test_an_uncomparable_version_against_a_bound_is_inconclusive() -> None:
    """Not in range, not out of range: undecided. Guessing "in" invents a finding; guessing
    "out" hides one."""
    assert version_in_range("unknown", end_excluding="2.4.58") is RangeVerdict.INCONCLUSIVE
    assert version_in_range(None, end_excluding="2.4.58") is RangeVerdict.INCONCLUSIVE


def test_no_version_against_an_unbounded_range_is_still_decidable() -> None:
    """If the CVE affects every version of the product, not knowing our version does not
    stop us knowing the answer."""
    assert version_in_range(None) is RangeVerdict.IN_RANGE
