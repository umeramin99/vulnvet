"""Data model: the claims vulnvet extracts and the verdicts it hands back.

A *claim* is a mechanically checkable assertion made by a vulnerability
report: "function X exists", "file Y has a bug at line N", "this code
appears in the tree", "version A through B are affected". A *finding*
pairs a claim with a verdict and the evidence behind it.

Verdict philosophy (this is the heart of the tool):

- ``VERIFIED``    — the claim corresponds to the codebase. This does NOT
                    validate the vulnerability logic itself, only that the
                    citation is real.
- ``NOT_FOUND``   — we looked in the right place and the cited thing does
                    not exist there. The strongest fabrication signal.
- ``MISMATCH``    — partially corroborated: the thing exists but a detail
                    is wrong (line past end of file, path in the wrong
                    directory, inverted version range).
- ``UNCHECKABLE`` — we could not verify it either way. Always the fallback
                    when extraction or the repository state leaves doubt.
                    vulnvet fails toward UNCHECKABLE, never toward a false
                    accusation.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class ClaimType(str, enum.Enum):
    FILE = "file"
    FILE_LINE = "file-line"
    SYMBOL = "symbol"
    STACK_FRAME = "stack-frame"
    QUOTED_CODE = "quoted-code"
    VERSION = "version"
    COMMIT = "commit"
    CVE = "cve"

    @property
    def label(self) -> str:
        return _TYPE_LABELS[self]


_TYPE_LABELS = {
    ClaimType.FILE: "Cited files",
    ClaimType.FILE_LINE: "File:line references",
    ClaimType.SYMBOL: "Cited symbols",
    ClaimType.STACK_FRAME: "Stack trace frames",
    ClaimType.QUOTED_CODE: "Quoted code",
    ClaimType.VERSION: "Version claims",
    ClaimType.COMMIT: "Commit references",
    ClaimType.CVE: "CVE identifiers",
}


class Verdict(str, enum.Enum):
    VERIFIED = "VERIFIED"
    NOT_FOUND = "NOT FOUND"
    MISMATCH = "MISMATCH"
    UNCHECKABLE = "UNCHECKABLE"


#: Claim types whose NOT_FOUND verdict is strong evidence of fabrication.
#: A fabricated function name or invented "quote" from the source tree is
#: much harder to explain innocently than a wrong version number.
STRONG_SIGNAL_TYPES = frozenset(
    {ClaimType.SYMBOL, ClaimType.STACK_FRAME, ClaimType.QUOTED_CODE}
)

#: Claim types whose VERIFIED verdict means the reporter demonstrably read
#: the code. Naming a real file path, a real release or a real CVE proves
#: only that they can read a directory listing, so those must not count
#: toward "this report is well grounded" - otherwise anyone can defuse the
#: escalation rule by padding a fabricated report with true trivia.
SUBSTANTIVE_TYPES = frozenset(
    {
        ClaimType.SYMBOL,
        ClaimType.STACK_FRAME,
        ClaimType.QUOTED_CODE,
        ClaimType.FILE_LINE,
    }
)


@dataclass
class Claim:
    type: ClaimType
    value: str
    #: 1-based line in the report where the claim appears.
    report_line: int = 0
    #: The report line (trimmed) the claim was pulled from, for context.
    context: str = ""
    #: Where the claim came from: "prose", "inline-code", "code-block", "diff".
    source: str = "prose"
    #: Type-specific payload (path, line number, sampled lines, ...).
    extra: Dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple:
        """Deduplication key."""
        if self.type is ClaimType.FILE_LINE:
            # The end of a range is part of the claim: without it,
            # "src/http.c:10" swallowed "src/http.c:10-9000" as a
            # duplicate and the fabricated end was never checked.
            return (
                self.type,
                self.extra.get("path"),
                self.extra.get("line"),
                self.extra.get("end_line"),
            )
        if self.type is ClaimType.STACK_FRAME:
            return (
                self.type,
                self.extra.get("function"),
                self.extra.get("path"),
                self.extra.get("line"),
            )
        if self.type is ClaimType.QUOTED_CODE:
            return (self.type, self.report_line)
        return (self.type, self.value)


@dataclass
class Finding:
    claim: Claim
    verdict: Verdict
    #: One or two sentences of concrete evidence for the verdict.
    evidence: str
    #: Optional "did you mean ...?" style hint.
    suggestion: Optional[str] = None

    @property
    def is_strong_signal(self) -> bool:
        return (
            self.verdict is Verdict.NOT_FOUND
            and self.claim.type in STRONG_SIGNAL_TYPES
        )


@dataclass
class Dossier:
    """Everything vulnvet concluded about one report against one revision."""

    report_path: str
    repo_path: str
    rev: str
    rev_sha: str
    findings: List[Finding] = field(default_factory=list)
    #: Non-fatal notes about the run (rev fallbacks, skipped content, ...).
    notes: List[str] = field(default_factory=list)
    #: Claims the extraction budget prevented us from checking, by type.
    #: While this is non-empty the dossier cannot certify the report:
    #: "every checkable claim corresponds to the codebase" is false when
    #: some claims were never looked at.
    dropped: Dict[str, int] = field(default_factory=dict)

    def count(self, verdict: Verdict) -> int:
        return sum(1 for f in self.findings if f.verdict is verdict)

    @property
    def strong_signals(self) -> List[Finding]:
        return [f for f in self.findings if f.is_strong_signal]

    @property
    def substantive_verified(self) -> int:
        """Verified claims that required reading the code, not listing it."""
        return sum(
            1
            for f in self.findings
            if f.verdict is Verdict.VERIFIED
            and f.claim.type in SUBSTANTIVE_TYPES
        )

    @property
    def checkable(self) -> int:
        return sum(
            1 for f in self.findings if f.verdict is not Verdict.UNCHECKABLE
        )

    def assessment(self) -> "Assessment":
        verified = self.count(Verdict.VERIFIED)
        not_found = self.count(Verdict.NOT_FOUND)
        mismatch = self.count(Verdict.MISMATCH)
        strong = len(self.strong_signals)

        if self.dropped and not (not_found or mismatch):
            total = sum(self.dropped.values())
            kinds = ", ".join(
                f"{n} {k}" for k, n in sorted(
                    self.dropped.items(), key=lambda kv: -kv[1]
                )
            )
            return Assessment(
                grade="COVERAGE INCOMPLETE",
                summary=(
                    f"Everything checked corresponds to the codebase, but "
                    f"{total} claim(s) were never checked because the report "
                    f"exceeded the extraction budget ({kinds}). This dossier "
                    "does not speak to them, so it cannot tell you the "
                    "report is sound - a report padded past the budget is "
                    "itself worth a second look."
                ),
            )
        if not self.findings:
            return Assessment(
                grade="NO CHECKABLE CLAIMS",
                summary=(
                    "The report contains no mechanically checkable claims "
                    "(no cited files, symbols, lines, code, versions, or "
                    "commits). That vagueness is itself a triage signal, "
                    "but it is not evidence of fabrication."
                ),
            )
        # One fabricated citation among many that check out is a
        # correction to ask for, not a pattern. Escalate on repetition, or
        # when failures clearly outweigh what the report got right - where
        # "got right" counts only claims that show the reporter read the
        # code, so a list of real filenames cannot buy its way out.
        failures = not_found + mismatch
        if strong >= 2 or (strong >= 1 and failures >= max(2, 2 * self.substantive_verified)):
            count_phrase = (
                "Multiple cited technical details do not exist"
                if failures > 1
                else "A cited technical detail does not exist"
            )
            return Assessment(
                grade="SEVERE GROUNDING FAILURES",
                summary=(
                    f"{count_phrase} in the codebase at the checked "
                    "revision, and little else in the report checks out. "
                    "This pattern is characteristic of fabricated reports. "
                    "Read the dossier below before responding to the "
                    "reporter."
                ),
            )
        if not_found or mismatch:
            opening = (
                "Some claims check out and some do not."
                if verified
                else "No claim checked out."
            )
            # A fabricated citation must never be buried by a favourable
            # ratio: padding a report with true trivia is cheap, so the
            # summary names the strong signal even when the grade does not
            # escalate.
            if strong:
                named = ", ".join(
                    f"'{f.claim.value}'" for f in self.strong_signals[:3]
                )
                opening += (
                    f" Note that {named} "
                    f"{'does' if strong == 1 else 'do'} not exist in the "
                    "codebase at all, which the rest of the report checking "
                    "out does not explain away."
                )
            return Assessment(
                grade="PARTIAL GROUNDING",
                summary=(
                    f"{opening} This can mean sloppiness, an honest mistake "
                    "(wrong version, renamed file), or partial fabrication - "
                    "read the per-claim evidence before judging."
                ),
            )
        # "Fully grounded" has to mean something was actually checked.
        # A report whose only successes are file paths, with its code
        # left ungraded, has not been vetted - saying otherwise would
        # certify exactly the blocks nobody looked at.
        if verified == 0 or (
            self.substantive_verified == 0 and self.count(Verdict.UNCHECKABLE)
        ):
            return Assessment(
                grade="UNCHECKABLE",
                summary=(
                    "Nothing in this report could be checked against the "
                    "code itself - what verified was file paths and "
                    "metadata, not anything showing the reporter read the "
                    "source. Read the per-claim notes; treat the report as "
                    "unvetted."
                ),
            )
        return Assessment(
            grade="FULLY GROUNDED",
            summary=(
                "Every checkable claim corresponds to the codebase at the "
                "checked revision. This does NOT validate the vulnerability "
                "logic itself - it means the report's citations are real "
                "and the report deserves a human read."
            ),
        )


#: Every grade :meth:`Dossier.assessment` can return. action.yml and the
#: README document this set for workflows that gate on it, and a test
#: pins all three together so a new grade cannot appear in one only.
GRADES = (
    "FULLY GROUNDED",
    "PARTIAL GROUNDING",
    "SEVERE GROUNDING FAILURES",
    "COVERAGE INCOMPLETE",
    "UNCHECKABLE",
    "NO CHECKABLE CLAIMS",
)


@dataclass
class Assessment:
    grade: str
    summary: str
