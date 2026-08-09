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
            return (self.type, self.extra.get("path"), self.extra.get("line"))
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

    def count(self, verdict: Verdict) -> int:
        return sum(1 for f in self.findings if f.verdict is verdict)

    @property
    def strong_signals(self) -> List[Finding]:
        return [f for f in self.findings if f.is_strong_signal]

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
        if strong >= 2 or (strong >= 1 and not_found > verified):
            return Assessment(
                grade="SEVERE GROUNDING FAILURES",
                summary=(
                    "Multiple cited technical details do not exist in the "
                    "codebase at the checked revision. This pattern is "
                    "characteristic of fabricated reports. Verify the "
                    "dossier below before responding to the reporter."
                ),
            )
        if not_found or mismatch:
            return Assessment(
                grade="PARTIAL GROUNDING",
                summary=(
                    "Some claims check out and some do not. This can mean "
                    "sloppiness, an honest mistake (wrong version, renamed "
                    "file), or partial fabrication - read the per-claim "
                    "evidence before judging."
                ),
            )
        if verified == 0:
            return Assessment(
                grade="UNCHECKABLE",
                summary=(
                    "Claims were extracted but none could be verified "
                    "against the repository (see per-claim notes). Treat "
                    "the report as unvetted."
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


@dataclass
class Assessment:
    grade: str
    summary: str
