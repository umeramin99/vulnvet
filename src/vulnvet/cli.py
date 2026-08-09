"""vulnvet command-line interface.

Exit codes (for CI / scripted triage):
  0 - every checkable claim grounded, or nothing checkable
  1 - at least one NOT FOUND or MISMATCH finding
  2 - usage or environment error (bad path, unresolvable rev, not a repo)
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .extract import extract_claims
from .gitrepo import GitError, NotARepository, Repo
from .report import render_json, render_markdown, render_terminal
from .verify import build_dossier
from .claims import Verdict


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnvet",
        description=(
            "Ground the claims in a vulnerability report against the actual "
            "codebase before you burn hours triaging it. Extracts cited "
            "files, symbols, lines, quoted code, versions and commits from "
            "the report, checks each against the git tree at the claimed "
            "revision, and emits an evidence dossier."
        ),
        epilog=(
            "examples:\n"
            "  vulnvet report.md --repo ~/src/curl --rev 8.9.0\n"
            "  gh issue view 1234 | vulnvet - --repo .\n"
            "  vulnvet report.md --repo . --format markdown -o dossier.md\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "report",
        help="path to the report (markdown, email, or plain text); '-' for stdin",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="path to the git repository to check against (default: .)",
    )
    parser.add_argument(
        "--rev",
        "-r",
        default=None,
        help=(
            "revision the report claims to be about: a tag, branch, SHA, or "
            "bare version like 8.9.0 (matched against tags). Default: HEAD"
        ),
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["term", "markdown", "json"],
        default=None,
        help=(
            "output format (default: term; inferred from -o extension when "
            "writing to a file)"
        ),
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="write the dossier to a file instead of stdout",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors (also honors NO_COLOR)",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="always exit 0 even when claims fail to ground",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"vulnvet {__version__}",
    )
    return parser


def _read_report(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _pick_format(args: argparse.Namespace) -> str:
    if args.format:
        return args.format
    if args.output:
        lowered = args.output.lower()
        if lowered.endswith((".md", ".markdown")):
            return "markdown"
        if lowered.endswith(".json"):
            return "json"
    return "term"


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        text = _read_report(args.report)
    except OSError as exc:
        print(f"vulnvet: cannot read report: {exc}", file=sys.stderr)
        return 2

    if not text.strip():
        print("vulnvet: the report is empty", file=sys.stderr)
        return 2

    try:
        repo = Repo(args.repo)
    except NotARepository as exc:
        print(f"vulnvet: {exc}", file=sys.stderr)
        return 2

    stats: dict = {}
    claims, notes = extract_claims(text, stats)

    try:
        dossier = build_dossier(
            report_path=args.report if args.report != "-" else "<stdin>",
            repo=repo,
            rev_input=args.rev,
            claims=claims,
            notes=notes,
            dropped=stats.get("dropped"),
        )
    except GitError as exc:
        print(f"vulnvet: {exc}", file=sys.stderr)
        return 2

    fmt = _pick_format(args)
    if fmt == "markdown":
        rendered = render_markdown(dossier)
    elif fmt == "json":
        rendered = render_json(dossier)
    else:
        stream = sys.stdout if not args.output else None
        rendered = render_terminal(
            dossier,
            no_color=args.no_color or bool(args.output),
            stream=stream,
        )

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered)
        except OSError as exc:
            print(f"vulnvet: cannot write output: {exc}", file=sys.stderr)
            return 2
        print(f"vulnvet: dossier written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)

    if args.exit_zero:
        return 0
    failed = dossier.count(Verdict.NOT_FOUND) + dossier.count(Verdict.MISMATCH)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
