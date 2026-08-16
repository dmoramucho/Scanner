"""`AdvisoryRetriever` — the only channel by which CVE knowledge reaches the model.

Half B's first step, and it produces no insight: it produces the *grounding* an insight will
have to cite. The rule it exists to enforce is AGENTS.md §4.8 — **ground, never recall**. An
LLM's CVE knowledge is stale, partial, and confidently wrong in exactly the way that is
hardest to notice; hallucinated CVE ids are its signature failure. So P16 gets no path to
CVE knowledge except this one, and everything here is built to make that channel trustworthy:

**Nothing is synthesized.** `advisory_text` is text somebody actually published, quoted,
with the source it came from attached to it. This module has no summariser, no paraphrase,
and no model import — `tests/test_adapter_boundaries.py` fails if that changes. The one
derived field, `fix_touched_summary`, is assembled mechanically out of a real patch (its
subject line and the paths it changed) and is left **empty when there is no patch to read**,
because a guess about what a fix touched is precisely the kind of plausible fiction the
whole architecture is arranged to keep out.

**Cache first.** The CVE record comes from P12's cache through the feed port, which already
answers from Postgres when it can. Fetched reference documents are cached by URL —
including the answer "there is nothing at this URL", so a dead reference is asked about
once rather than every run.

**Everything fetched is hostile until defanged.** Advisory text is attacker-influenced: a
CVE's description and its references are written by people, sometimes by the people whose
software the CVE is about. That text is going into a prompt, so it is sanitised in
`sanitize.py` *before it is cached*, and the cache therefore holds only safe text.

**Only patches are fetched, and only from code hosts.** Anyone can attach a reference URL
to a CVE, and this process runs inside a corporate network — fetching arbitrary references
would be a server-side request forgery primitive pointed at the estate we are supposed to
be protecting. So an outbound fetch requires https, a host on `PATCH_HOSTS`, and a
patch-shaped path. Everything else is used as a citation, never dereferenced.

**Absence and failure are different answers, and neither is an empty string.** No advisory
text raises `NotFoundError` — P16 must refuse to reason rather than fall back on memory. An
unreachable source raises `DependencyError(retryable=True)`. What never happens is an
`AdvisoryEvidence` whose `advisory_text` is empty, which would look like grounding and be
nothing (AGENTS.md §67).
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final
from urllib.parse import urlsplit

from adapters.advisory.sanitize import (
    MAX_TEXT_CHARS,
    SanitizedText,
    marker,
    sanitize,
    sanitize_line,
)
from adapters.feed.http import HttpClient, HttpxClient
from domain.errors import NotFoundError, ValidationError
from domain.models import (
    AdvisoryDocument,
    AdvisoryDocumentStatus,
    AdvisoryEvidence,
    AdvisoryRetrievalReport,
    CveRecord,
)
from domain.ports import AdvisoryDocumentCache, VulnerabilityFeed

#: Hosts we are willing to make an outbound request to. Not a convenience list — it is the
#: SSRF boundary. A reference URL is attacker-influenced input, and this process sits inside
#: the network it is scanning (AGENTS.md §2.9).
PATCH_HOSTS: Final = frozenset(
    {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "gitea.com",
        "git.kernel.org",
        "sourceware.org",
        "git.savannah.gnu.org",
        "gitbox.apache.org",
    }
)

#: Host suffixes covered by the same allowance (Google's git hosting is per-project).
PATCH_HOST_SUFFIXES: Final = (".googlesource.com",)

#: Path shapes that mean "this reference is a commit or a diff" rather than a web page.
_PATCH_PATH = re.compile(
    r"/-?/?commits?/[0-9a-f]{7,40}"  # github, gitea, gitlab (/-/commit/<sha>)
    r"|\.(?:patch|diff)$"
    r"|/commit/\?id=|;a=(?:commit|commitdiff)|/patch/\?id=",  # cgit / gitweb
    re.IGNORECASE,
)

_COMMIT_SHA = re.compile(r"/commits?/([0-9a-f]{7,40})", re.IGNORECASE)

#: Unified-diff file headers. `diff --git a/x b/y` and `+++ b/path` between them cover git,
#: `git format-patch`, and plain `diff -u` output.
_DIFF_GIT = re.compile(r"^diff --git a/(\S+) b/(\S+)", re.MULTILINE)
_DIFF_PLUS = re.compile(r"^\+\+\+ (?:b/)?(\S+)", re.MULTILINE)
_PATCH_SUBJECT = re.compile(r"^Subject:\s*(?:\[[^\]\n]{0,40}\]\s*)?(.+)$", re.MULTILINE)

#: A patch bigger than this is not a fix we can usefully summarise; it is a vendored tree.
MAX_DOCUMENT_BYTES: Final = 2 * 1024 * 1024

#: Bounds on the assembled evidence. The prompt in P16 has a budget and this is most of it.
MAX_EVIDENCE_CHARS: Final = 16_000
MAX_CITED_REFERENCES: Final = 10
MAX_SUMMARY_FILES: Final = 12

#: HTTP statuses that settle the question: there is nothing at this URL, and asking again
#: tomorrow will not change that. Anything else is "we could not get it *this time*".
_DEFINITIVE_MISSING: Final = frozenset({401, 403, 404, 410, 451})


class HttpAdvisoryRetriever:
    """`AdvisoryRetriever` over the cached NVD record plus, where one exists, the fix patch.

    `client=None` is a supported configuration and not a degraded one: it yields a retriever
    that grounds entirely on what is already cached and never makes an outbound request.
    """

    def __init__(
        self,
        feed: VulnerabilityFeed,
        documents: AdvisoryDocumentCache,
        *,
        client: HttpClient | None = None,
        fetch_fix_documents: bool = True,
        timeout_seconds: float = 15.0,
        min_interval_seconds: float = 1.0,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._feed = feed
        self._documents = documents
        if client is not None:
            self._client: HttpClient | None = client
        else:
            self._client = HttpxClient() if fetch_fix_documents else None
        self._fetch_documents = fetch_fix_documents
        self._timeout = timeout_seconds
        self._min_interval = min_interval_seconds
        self._clock = clock
        self._sleep = sleep
        self._monotonic = monotonic
        self._last_request_at: float | None = None
        self._report = AdvisoryRetrievalReport()

    # ------------------------------------------------------------------- the port

    def fetch(self, cve_id: str, matched_cpe: str) -> AdvisoryEvidence:
        """Grounding material for one match. See the port contract in `domain.ports`.

        `matched_cpe` is validated and otherwise unused today: retrieval is per-CVE, and the
        parameter is where per-product source selection (a GHSA for the ecosystem, a vendor
        advisory for the platform) will hook in. Validated anyway, because a value crossing
        this boundary unchecked is a habit, not an exception (AGENTS.md §2.9).
        """
        identifier = _validated_cve_id(cve_id)
        _validated_cpe(matched_cpe)
        self._report.fetches += 1

        # Raises `DependencyError` if NVD cannot be reached — never an empty record. The
        # cache in front of it means most calls make no request at all (ADR-0010).
        record = self._feed.cve(identifier)
        if record is None:
            # The feed answered, and its answer is that it has no such CVE. There is nothing
            # to ground on, so say so rather than handing back an empty advisory.
            raise NotFoundError(
                f"no advisory record exists for {identifier}; there is nothing to ground on"
            )

        sections: list[_Section] = []
        description = sanitize(record.description, limit=MAX_TEXT_CHARS)
        self._count(description)
        if description.text:
            sections.append(_Section(source=_record_source(record), text=description.text))

        fix_ref = self._fix_reference(record)
        fix_document = self._fix_document(fix_ref, identifier) if fix_ref else None
        fix_summary = _fix_touched_summary(fix_document) if fix_document else None
        if fix_document is not None and fix_document.content:
            sections.append(
                _Section(source=fix_document.url, text=_quoted_patch(fix_document.content))
            )

        citations = _citable_references(record)
        if not sections:
            # Reachable sources, and none of them had text. A URL list is provenance, not
            # advisory text — grounding an insight on it would be grounding on nothing.
            raise NotFoundError(
                f"no advisory text could be sourced for {identifier} "
                f"({len(citations)} reference(s) cited, none quotable)"
            )

        return AdvisoryEvidence(
            advisory_id=identifier,
            advisory_source=_provenance(sections, citations),
            advisory_text=_assemble(sections, citations),
            fix_diff_ref=fix_ref,
            fix_touched_summary=fix_summary,
        )

    def retrieval_report(self) -> AdvisoryRetrievalReport:
        """What retrieval has done since construction, including what it had to defuse.

        Not part of the port: the port's job is evidence. This is how an operator finds out
        that three of last night's advisories contained text addressed to a model.
        """
        return self._report

    # ------------------------------------------------------------- reference handling

    def _fix_reference(self, record: CveRecord) -> str | None:
        """The first reference that points at a commit or a diff we are allowed to fetch.

        Both halves matter. Patch-shaped, so we are not downloading web pages; on an
        allowlisted host, so a reference nobody vetted cannot aim this process at
        `169.254.169.254` or at a colleague's intranet box.
        """
        for url in record.references:
            if _is_fetchable_patch(url):
                return url
        return None

    def _fix_document(self, url: str, cve_id: str) -> AdvisoryDocument | None:
        """The patch behind a fix reference, from cache or from the network.

        Returns None when there is nothing usable — a dead link, a fetch that failed, a
        retriever configured not to fetch. That is a *graceful degradation*, and it is safe
        precisely because it degrades a supplementary field: `fix_diff_ref` still names the
        commit, so the evidence says "there is a fix here and we have no summary of it"
        rather than implying there is no fix.
        """
        target = _patch_url(url)

        cached = self._documents.document(target)
        if cached is not None:
            # Includes the negative answer: a reference already established to be dead is
            # not re-fetched. `None` means never asked; `unavailable` means asked.
            self._report.served_from_cache += 1
            return cached if cached.usable else None

        if self._client is None or not self._fetch_documents:
            return None

        document = self._retrieve(target, cve_id)
        if document is None:
            return None
        self._documents.store(document)
        return document if document.usable else None

    def _retrieve(self, url: str, cve_id: str) -> AdvisoryDocument | None:
        """One outbound GET, or None if it did not produce a storable answer.

        The distinction drawn here is the one that keeps the cache honest: a 404 is a *fact*
        about the reference and is stored, so we stop asking. A timeout is not an answer at
        all and is stored nowhere — tomorrow's run tries again (AGENTS.md §67).
        """
        if self._client is None:  # pragma: no cover — guarded by the caller
            return None

        self._respect_rate_limit()
        try:
            response = self._client.get(url, params={}, headers=_HEADERS, timeout=self._timeout)
        except OSError:
            self._report.unavailable_references += 1
            return None

        if response.status_code in _DEFINITIVE_MISSING:
            self._report.unavailable_references += 1
            return AdvisoryDocument(
                url=url,
                status=AdvisoryDocumentStatus.UNAVAILABLE,
                cve_id=cve_id,
                fetched_at=self._clock(),
                raw_record_ref=url,
            )

        if response.status_code != 200 or len(response.body) > MAX_DOCUMENT_BYTES:
            # A 500 may succeed later; an oversized body is not something to keep retrying,
            # but neither is it evidence that the reference is dead. Cache neither.
            self._report.unavailable_references += 1
            return None

        # Decoded leniently and sanitised immediately: from here on the text is safe, and
        # nothing downstream — including the cache — ever sees the raw bytes (ADR-0013).
        clean = sanitize(response.body.decode("utf-8", errors="replace"), limit=MAX_TEXT_CHARS)
        self._count(clean)
        self._report.fetched_from_source += 1

        if not clean.text:
            self._report.unavailable_references += 1
            return AdvisoryDocument(
                url=url,
                status=AdvisoryDocumentStatus.UNAVAILABLE,
                cve_id=cve_id,
                fetched_at=self._clock(),
                raw_record_ref=url,
            )

        return AdvisoryDocument(
            url=url,
            status=AdvisoryDocumentStatus.OK,
            content=clean.text,
            content_hash=hashlib.sha256(clean.text.encode("utf-8")).hexdigest(),
            media_type=str(response.headers.get("content-type", "")).split(";")[0] or None,
            cve_id=cve_id,
            fetched_at=self._clock(),
            raw_record_ref=url,
        )

    def _respect_rate_limit(self) -> None:
        """One request at a time, spaced. We are a guest on somebody else's git host."""
        if self._last_request_at is not None:
            elapsed = self._monotonic() - self._last_request_at
            if elapsed < self._min_interval:
                self._sleep(self._min_interval - elapsed)
        self._last_request_at = self._monotonic()

    def _count(self, clean: SanitizedText) -> None:
        """Fold one sanitisation result into the run's report.

        Every piece of untrusted text passes through here, so a hostile advisory is counted
        whether it arrived in a description or in a fetched patch.
        """
        self._report.neutralized_control_tokens += clean.control_tokens
        self._report.neutralized_injections += clean.injections
        self._report.truncated_documents += int(clean.truncated)


# --------------------------------------------------------------------- assembly


@dataclass(frozen=True, slots=True)
class _Section:
    """One quoted piece of evidence and the source it was quoted from."""

    source: str
    text: str


def _assemble(sections: Sequence[_Section], citations: Sequence[str]) -> str:
    """Join the quoted sections, each under a header naming its source.

    The headers use the reserved `[[…]]` family, which the sanitiser has already broken
    apart everywhere it appeared in fetched text — so a hostile advisory cannot forge a
    section header and attribute its own words to NVD.
    """
    parts = [f"{marker('source', section.source)}\n{section.text}" for section in sections]
    if citations:
        listed = "\n".join(citations)
        parts.append(f"{marker('references')}\n{listed}")

    assembled = "\n\n".join(parts)
    if len(assembled) > MAX_EVIDENCE_CHARS:
        omitted = len(assembled) - MAX_EVIDENCE_CHARS
        assembled = (
            assembled[:MAX_EVIDENCE_CHARS].rstrip()
            + "\n"
            + marker("truncated", f"{omitted} characters omitted")
        )
    return assembled


def _provenance(sections: Sequence[_Section], citations: Sequence[str]) -> str:
    """Where every quoted piece came from, in the order it appears in the text.

    One string because that is the contract's shape (dossier §6); every source in it, so a
    citation can be checked against the thing it claims to cite.
    """
    sources = [section.source for section in sections]
    if citations:
        sources.append(f"{len(citations)} cited reference(s)")
    return "; ".join(sources)


def _record_source(record: CveRecord) -> str:
    """The feed record's own provenance pointer, which P12 already maintains."""
    return record.raw_record_ref or f"{record.source}:{record.cve_id}"


def _citable_references(record: CveRecord) -> list[str]:
    """Reference URLs, bounded and re-validated.

    Quoted as provenance only. They are never dereferenced (except a fix patch, above) and
    never treated as advisory text: a URL is where evidence lives, not evidence.
    """
    citations: list[str] = []
    for url in record.references:
        candidate = sanitize_line(url, limit=300)
        if candidate.startswith(("http://", "https://")) and candidate not in citations:
            citations.append(candidate)
        if len(citations) >= MAX_CITED_REFERENCES:
            break
    return citations


def _quoted_patch(content: str) -> str:
    """The patch's own header lines, quoted — the part that reads as prose.

    The diff body is not quoted into the advisory text: it is machine detail, it is large,
    and what it means is already captured factually in `fix_touched_summary`.
    """
    lines: list[str] = []
    for line in content.splitlines():
        if line.startswith(("diff --git", "index ", "--- ", "+++ ", "@@")):
            break
        lines.append(line)
        if len(lines) >= 40:
            break
    return "\n".join(lines).strip()


def _fix_touched_summary(document: AdvisoryDocument) -> str | None:
    """What the fix changed, stated factually or not at all.

    Two things are extracted, both quoted from the patch rather than characterised: the
    commit subject, and the paths the diff touches. If the document is not a diff — a web
    page, a release note, anything unparseable — this returns None. An empty summary is a
    fact ("we have no patch to read"); an invented one would be the model's problem to
    unlearn later (AGENTS.md §4.8).
    """
    if not document.content:
        return None

    files = _changed_files(document.content)
    subject = _patch_subject(document.content)
    if not files and not subject:
        return None

    parts = [f"fix patch: {document.url}"]
    if subject:
        parts.append(f'commit subject: "{subject}"')
    if files:
        shown = ", ".join(files[:MAX_SUMMARY_FILES])
        more = "" if len(files) <= MAX_SUMMARY_FILES else f" (+{len(files) - MAX_SUMMARY_FILES})"
        parts.append(f"touched {len(files)} file(s): {shown}{more}")
    return "; ".join(parts)


def _changed_files(content: str) -> list[str]:
    """Every path the diff touches, deduplicated, in the order they appear."""
    paths: list[str] = []
    for match in _DIFF_GIT.finditer(content):
        paths.extend(match.group(1, 2))
    if not paths:
        paths = [match.group(1) for match in _DIFF_PLUS.finditer(content)]

    seen: list[str] = []
    for path in paths:
        cleaned = sanitize_line(path, limit=120)
        if cleaned and cleaned != "/dev/null" and cleaned not in seen:
            seen.append(cleaned)
        if len(seen) >= 200:
            break
    return seen


def _patch_subject(content: str) -> str | None:
    """The commit subject from a `git format-patch` header, quoted verbatim."""
    match = _PATCH_SUBJECT.search(content)
    if match is None:
        return None
    return sanitize_line(match.group(1)) or None


# --------------------------------------------------------------------- validation


_HEADERS: Final = {"Accept": "text/plain, application/octet-stream", "User-Agent": "scanner/p15"}


def _is_fetchable_patch(url: str) -> bool:
    """Is this reference a commit/diff on a host we are willing to contact?

    Deliberately strict on three axes: scheme (https only — a plaintext fetch inside a
    corporate network is both interceptable and a redirect away from anywhere), host (an
    allowlist, because reference URLs are attacker-influenced), and path shape (a patch, not
    a page). A reference failing any of them is still cited; it is simply not dereferenced.
    """
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return False

    if parts.scheme != "https" or not parts.hostname:
        return False
    host = parts.hostname.lower()
    if host not in PATCH_HOSTS and not host.endswith(PATCH_HOST_SUFFIXES):
        return False
    if parts.port not in (None, 443):
        return False
    return bool(_PATCH_PATH.search(parts.path) or _PATCH_PATH.search(f"{parts.path}?{parts.query}"))


def _patch_url(url: str) -> str:
    """The machine-readable form of a commit reference, where one is known.

    GitHub and GitLab both serve `<commit-url>.patch`: a documented, stable transformation
    that turns an HTML page into a real diff. Nothing is invented — if the host has no such
    convention, the original URL is fetched as-is and simply may not parse as a diff, which
    leaves the summary empty rather than wrong.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    known_convention = host in {"github.com", "gitlab.com"} and bool(_COMMIT_SHA.search(parts.path))
    if known_convention and not parts.path.endswith((".patch", ".diff")):
        return f"https://{parts.netloc}{parts.path.rstrip('/')}.patch"
    return url


def _validated_cve_id(cve_id: str) -> str:
    """A CVE id, or nothing. It becomes a cache key and a lookup, so it is checked here."""
    candidate = cve_id.strip().upper()
    parts = candidate.split("-")
    if len(parts) != 3 or parts[0] != "CVE" or not parts[1].isdigit() or not parts[2].isdigit():
        raise ValidationError(f"not a CVE id: {cve_id[:40]!r}")
    return candidate


def _validated_cpe(cpe: str) -> str:
    candidate = cpe.strip()
    if not candidate.startswith("cpe:2.3:") or len(candidate) > 500:
        raise ValidationError(f"not a CPE 2.3 string: {candidate[:80]!r}")
    return candidate


__all__: Sequence[str] = [
    "MAX_EVIDENCE_CHARS",
    "PATCH_HOSTS",
    "HttpAdvisoryRetriever",
]
