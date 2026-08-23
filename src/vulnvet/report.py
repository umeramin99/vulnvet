"""Render a dossier as a terminal report, a markdown dossier, or JSON.

The markdown dossier is written to be pasted directly into the issue or
bug-bounty thread: per-claim evidence a reporter can respond to, plus an
explicit disclaimer of what the tool does and does not conclude.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import List

from .claims import ClaimType, Dossier, Finding, Verdict

DISCLAIMER = (
    "vulnvet grounds a report's citations against the codebase; it does "
    "not judge the vulnerability logic itself, and it cannot tell who or "
    "what wrote the report. NOT FOUND means a specific cited detail does "
    "not exist at the checked revision - give the reporter a chance to "
    "correct an honest mistake (wrong version, typo) before concluding "
    "fabrication."
)

_ORDER = [
    ClaimType.SYMBOL,
    ClaimType.STACK_FRAME,
    ClaimType.QUOTED_CODE,
    ClaimType.FILE_LINE,
    ClaimType.FILE,
    ClaimType.VERSION,
    ClaimType.COMMIT,
    ClaimType.CVE,
]

_GLYPH = {
    Verdict.VERIFIED: "+",
    Verdict.NOT_FOUND: "x",
    Verdict.MISMATCH: "~",
    Verdict.UNCHECKABLE: "?",
}

_MD_BADGE = {
    Verdict.VERIFIED: "✅ VERIFIED",
    Verdict.NOT_FOUND: "❌ NOT FOUND",
    Verdict.MISMATCH: "⚠️ MISMATCH",
    Verdict.UNCHECKABLE: "❔ UNCHECKABLE",
}


class _Palette:
    def __init__(self, enabled: bool):
        if enabled:
            self.green = "\x1b[32m"
            self.red = "\x1b[31m"
            self.yellow = "\x1b[33m"
            self.dim = "\x1b[2m"
            self.bold = "\x1b[1m"
            self.reset = "\x1b[0m"
        else:
            self.green = self.red = self.yellow = ""
            self.dim = self.bold = self.reset = ""

    def for_verdict(self, verdict: Verdict) -> str:
        return {
            Verdict.VERIFIED: self.green,
            Verdict.NOT_FOUND: self.red,
            Verdict.MISMATCH: self.yellow,
            Verdict.UNCHECKABLE: self.dim,
        }[verdict]


def color_enabled(no_color_flag: bool, stream) -> bool:
    if no_color_flag:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


#: Control characters, including ESC. A report is attacker-controlled
#: text, and vulnvet echoes pieces of it back (claim values, the line a
#: claim came from). Without this, a reporter can embed ANSI sequences
#: that repaint the terminal and forge verdict lines in vulnvet's own
#: output - the one place a maintainer is entitled to trust.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize(text: str) -> str:
    """Make report-derived text safe to print, in any format."""
    if not text:
        return ""
    return _CONTROL_RE.sub("�", text.replace("\t", " "))


def _md_cell(text: str) -> str:
    """Sanitized and escaped for a markdown table cell."""
    return (
        sanitize(text)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", " ")
    )


def _repo_label(path: str) -> str:
    """The repository's name, without the surrounding filesystem path."""
    name = os.path.basename(os.path.abspath(path))
    return name or path


def _grouped(dossier: Dossier) -> List[tuple]:
    groups = []
    for ctype in _ORDER:
        findings = [f for f in dossier.findings if f.claim.type is ctype]
        if findings:
            findings.sort(
                key=lambda f: (
                    0 if f.verdict is Verdict.NOT_FOUND else
                    1 if f.verdict is Verdict.MISMATCH else
                    2 if f.verdict is Verdict.VERIFIED else 3
                )
            )
            groups.append((ctype, findings))
    return groups


# --------------------------------------------------------------------------
# terminal
# --------------------------------------------------------------------------

def render_terminal(dossier: Dossier, no_color: bool = False, stream=None) -> str:
    stream = stream or sys.stdout
    p = _Palette(color_enabled(no_color, stream))
    a = dossier.assessment()
    lines: List[str] = []
    add = lines.append

    add(f"{p.bold}vulnvet{p.reset} - grounding {sanitize(dossier.report_path)}")
    add(
        f"  against {dossier.repo_path} at {p.bold}{dossier.rev}{p.reset} "
        f"({dossier.rev_sha[:12]})"
    )
    add("")

    for ctype, findings in _grouped(dossier):
        add(f"{p.bold}{ctype.label}{p.reset}")
        for f in findings:
            color = p.for_verdict(f.verdict)
            glyph = _GLYPH[f.verdict]
            add(
                f"  {color}{glyph} [{f.verdict.value:<11}]{p.reset} "
                f"{sanitize(f.claim.value)}"
            )
            add(f"      {p.dim}{sanitize(f.evidence)}{p.reset}")
            if f.suggestion:
                add(f"      {p.dim}hint: {sanitize(f.suggestion)}{p.reset}")
            if f.claim.report_line:
                add(
                    f"      {p.dim}report line {f.claim.report_line}: "
                    f"{sanitize(f.claim.context)[:100]}{p.reset}"
                )
        add("")

    verified = dossier.count(Verdict.VERIFIED)
    not_found = dossier.count(Verdict.NOT_FOUND)
    mismatch = dossier.count(Verdict.MISMATCH)
    uncheckable = dossier.count(Verdict.UNCHECKABLE)
    strong = len(dossier.strong_signals)

    add(f"{p.bold}Summary{p.reset}")
    add(
        f"  {p.green}{verified} verified{p.reset}   "
        f"{p.red}{not_found} not found{p.reset}   "
        f"{p.yellow}{mismatch} mismatched{p.reset}   "
        f"{p.dim}{uncheckable} uncheckable{p.reset}"
    )
    if strong:
        add(
            f"  {p.red}{strong} strong fabrication signal(s): cited "
            f"symbols/frames/quotes that do not exist in the tree{p.reset}"
        )
    grade_color = (
        p.red if "SEVERE" in a.grade
        else p.yellow if a.grade in ("PARTIAL GROUNDING", "UNCHECKABLE", "NO CHECKABLE CLAIMS")
        else p.green
    )
    add("")
    add(f"  {grade_color}{p.bold}{a.grade}{p.reset}")
    add(f"  {a.summary}")
    for note in dossier.notes:
        add(f"  {p.dim}note: {sanitize(note)}{p.reset}")
    add("")
    add(f"  {p.dim}{DISCLAIMER}{p.reset}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# markdown
# --------------------------------------------------------------------------

def render_markdown(dossier: Dossier) -> str:
    a = dossier.assessment()
    lines: List[str] = []
    add = lines.append

    add("## vulnvet triage dossier")
    add("")
    add(f"**Report:** `{_md_cell(os.path.basename(dossier.report_path))}`  ")
    # The markdown dossier is meant to be pasted into a public ticket, so
    # it names the repository, not the maintainer's directory layout. The
    # revision is what makes the result reproducible anyway.
    add(
        f"**Checked against:** `{_repo_label(dossier.repo_path)}` at "
        f"`{dossier.rev}` (`{dossier.rev_sha[:12]}`)  "
    )
    add(f"**Assessment: {a.grade}**")
    add("")
    add(a.summary)
    add("")

    verified = dossier.count(Verdict.VERIFIED)
    not_found = dossier.count(Verdict.NOT_FOUND)
    mismatch = dossier.count(Verdict.MISMATCH)
    uncheckable = dossier.count(Verdict.UNCHECKABLE)
    add(
        f"| ✅ verified | ❌ not found | ⚠️ mismatched | ❔ uncheckable |"
    )
    add("|---:|---:|---:|---:|")
    add(f"| {verified} | {not_found} | {mismatch} | {uncheckable} |")
    add("")

    for ctype, findings in _grouped(dossier):
        add(f"### {ctype.label}")
        add("")
        add("| verdict | claim | evidence |")
        add("|---|---|---|")
        for f in findings:
            evidence = _md_cell(f.evidence)
            if f.suggestion:
                evidence += f" *{_md_cell(f.suggestion)}*"
            claim_cell = "`" + _md_cell(f.claim.value).replace("`", "'") + "`"
            if f.claim.report_line:
                claim_cell += f" (report line {f.claim.report_line})"
            add(f"| {_MD_BADGE[f.verdict]} | {claim_cell} | {evidence} |")
        add("")

    if dossier.notes:
        add("### Notes")
        add("")
        for note in dossier.notes:
            add(f"- {_md_cell(note)}")
        add("")

    add("---")
    add(f"*{DISCLAIMER}*")
    add("")
    add(
        "*Generated by [vulnvet](https://github.com/umeramin99/vulnvet) - "
        "mechanical claim-grounding for vulnerability reports.*"
    )
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# json
# --------------------------------------------------------------------------

def render_json(dossier: Dossier) -> str:
    a = dossier.assessment()

    def finding_dict(f: Finding) -> dict:
        return {
            "type": f.claim.type.value,
            "claim": sanitize(f.claim.value),
            "verdict": f.verdict.name,
            "evidence": f.evidence,
            "suggestion": f.suggestion,
            "strong_signal": f.is_strong_signal,
            "report_line": f.claim.report_line,
            "context": sanitize(f.claim.context),
            "details": {
                k: v for k, v in f.claim.extra.items()
                if isinstance(v, (str, int, float, bool, type(None)))
            },
            "source": f.claim.source,
        }

    payload = {
        "tool": "vulnvet",
        "report": dossier.report_path,
        "repo": dossier.repo_path,
        "rev": dossier.rev,
        "rev_sha": dossier.rev_sha,
        "assessment": {"grade": a.grade, "summary": a.summary},
        "counts": {
            "verified": dossier.count(Verdict.VERIFIED),
            "not_found": dossier.count(Verdict.NOT_FOUND),
            "mismatch": dossier.count(Verdict.MISMATCH),
            "uncheckable": dossier.count(Verdict.UNCHECKABLE),
            "strong_signals": len(dossier.strong_signals),
        },
        "findings": [finding_dict(f) for f in dossier.findings],
        "notes": dossier.notes,
        "disclaimer": DISCLAIMER,
    }
    return json.dumps(payload, indent=2) + "\n"
