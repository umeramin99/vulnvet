"""Grade extracted claims against the repository at a pinned revision.

Every check here asks one narrow question and reports concrete evidence
either way. When the repository state leaves any doubt (no tags to check
versions against, unresolvable paths, ambiguous matches) the verdict is
UNCHECKABLE - never a guessed accusation.
"""

from __future__ import annotations

import datetime
import difflib
import re
from typing import List, Optional, Tuple

from .claims import Claim, ClaimType, Dossier, Finding, Verdict
from .gitrepo import GitError, Repo, _normalize_version_text


#: Files that are documentation, not source: a symbol living ONLY here
#: was never code the project shipped.
_DOC_EXTS = (".md", ".markdown", ".rst", ".txt", ".adoc", ".textile", ".org")
_DOC_BASENAMES = ("changelog", "changes", "news", "history", "authors", "thanks")


def _is_doc_path(path: str) -> bool:
    lower = path.lower()
    if lower.endswith(_DOC_EXTS):
        return True
    base = lower.rsplit("/", 1)[-1]
    return any(base.startswith(b) for b in _DOC_BASENAMES)


def _is_bare_document(path: str) -> bool:
    """A directory-less document name, e.g. ``report.md`` or ``notes.txt``.

    ``docs/SECURITY.md`` is a real path claim; a bare ``report.md`` is
    almost always the reporter naming an attachment.
    """
    return "/" not in path and path.lower().endswith(_DOC_EXTS)


class Verifier:
    def __init__(
        self,
        repo: Repo,
        rev: str,
        display: Optional[str] = None,
        exclude_paths: Optional[List[str]] = None,
    ):
        self.repo = repo
        #: Revision used for git queries (a resolved SHA).
        self.sha = rev
        #: Human-readable name used in evidence strings.
        self.rev = display or rev[:12]
        #: Pathspecs excluded from corroboration searches - at minimum the
        #: report file itself, when it lives inside the repo: a report must
        #: never corroborate itself.
        self.excludes = list(exclude_paths or [])
        self._tree = repo.tree_files(rev)
        self._tree_set = set(self._tree)
        self._basenames: dict = {}
        for path in self._tree:
            self._basenames.setdefault(path.rsplit("/", 1)[-1], []).append(path)

    # ------------------------------------------------------------ dispatch

    def verify(self, claim: Claim) -> Finding:
        try:
            handler = {
                ClaimType.FILE: self._verify_file,
                ClaimType.FILE_LINE: self._verify_file_line,
                ClaimType.SYMBOL: self._verify_symbol,
                ClaimType.STACK_FRAME: self._verify_stack_frame,
                ClaimType.QUOTED_CODE: self._verify_quoted_code,
                ClaimType.VERSION: self._verify_version,
                ClaimType.COMMIT: self._verify_commit,
                ClaimType.CVE: self._verify_cve,
            }[claim.type]
            return handler(claim)
        except GitError as exc:
            return Finding(
                claim,
                Verdict.UNCHECKABLE,
                f"git lookup failed while checking this claim: {exc}",
            )

    # ------------------------------------------------------------- helpers

    def _resolve_path(self, path: str) -> Optional[str]:
        """Exact path in tree, or unique suffix match (handles absolute
        build paths like /src/project/lib/http.c)."""
        if path in self._tree_set:
            return path
        stripped = path.lstrip("/")
        if stripped in self._tree_set:
            return stripped
        suffix_hits = [
            p for p in self._tree
            if p.endswith("/" + stripped) or (stripped.endswith("/" + p))
        ]
        if len(suffix_hits) == 1:
            return suffix_hits[0]
        return None

    def _suggest_path(self, path: str) -> Optional[Tuple[str, bool]]:
        """(suggested_path, exact_basename_match) or None.

        An exact basename elsewhere in the tree is strong evidence of a
        wrong directory; a fuzzy match (ngtcp2.c ~ curl_ngtcp2.c) is only
        a hint and must not soften the verdict.
        """
        base = path.rsplit("/", 1)[-1]
        hits = self._basenames.get(base, [])
        if hits:
            return hits[0], True
        close = difflib.get_close_matches(
            base, list(self._basenames), n=1, cutoff=0.7
        )
        if close:
            return self._basenames[close[0]][0], False
        return None

    # ---------------------------------------------------------------- FILE

    def _verify_file(self, claim: Claim) -> Finding:
        path = claim.extra.get("path", claim.value)
        resolved = self._resolve_path(path)
        if resolved is None and _is_bare_document(path):
            # "see report.md" / "attached notes.txt" names an attachment,
            # not a path in the tree. Grading it NOT FOUND would be an
            # accusation about the reporter's filing habits.
            return Finding(
                claim, Verdict.UNCHECKABLE,
                "reads as a reference to an attached document rather than a "
                "path in the repository",
            )
        if resolved:
            note = "" if resolved == path else f" (as {resolved})"
            return Finding(
                claim, Verdict.VERIFIED,
                f"file exists in the tree at {self.rev}{note}",
            )
        suggested = self._suggest_path(path)
        if suggested and suggested[1]:
            return Finding(
                claim,
                Verdict.MISMATCH,
                f"no file at this path at {self.rev}, but a file with the "
                f"same name exists elsewhere",
                suggestion=f"did the reporter mean {suggested[0]}?",
            )
        return Finding(
            claim, Verdict.NOT_FOUND,
            f"no such file anywhere in the tree at {self.rev} "
            f"({len(self._tree)} files checked)",
            suggestion=(
                f"closest real file: {suggested[0]}" if suggested else None
            ),
        )

    # ----------------------------------------------------------- FILE_LINE

    def _verify_file_line(self, claim: Claim) -> Finding:
        path = claim.extra["path"]
        line = claim.extra["line"]
        resolved = self._resolve_path(path)
        if not resolved:
            suggested = self._suggest_path(path)
            if suggested and suggested[1]:
                return Finding(
                    claim,
                    Verdict.MISMATCH,
                    f"no file at this path at {self.rev}",
                    suggestion=f"did the reporter mean {suggested[0]}?",
                )
            return Finding(
                claim, Verdict.NOT_FOUND,
                f"no such file anywhere in the tree at {self.rev}",
                suggestion=(
                    f"closest real file: {suggested[0]}" if suggested else None
                ),
            )
        count = self.repo.line_count(self.sha, resolved)
        if count is None:
            return Finding(
                claim, Verdict.UNCHECKABLE,
                f"{resolved} exists but its contents could not be read",
            )
        if line > count:
            return Finding(
                claim,
                Verdict.MISMATCH,
                f"{resolved} exists but has only {count} lines at {self.rev}; "
                f"the report cites line {line}",
            )
        text = self.repo.line_at(self.sha, resolved, line) or ""
        snippet = text.strip()[:80]
        return Finding(
            claim, Verdict.VERIFIED,
            f"{resolved}:{line} exists at {self.rev}"
            + (f' - reads: "{snippet}"' if snippet else " (blank line)"),
        )

    # -------------------------------------------------------------- SYMBOL

    def _verify_symbol(self, claim: Claim) -> Finding:
        name = claim.value
        hits = self.repo.grep_word(self.sha, name, excludes=self.excludes)
        if not hits and "::" in name:
            # Qualified C++ name: fall back to the method part.
            method = name.rsplit("::", 1)[-1]
            if len(method) >= 4:
                hits = self.repo.grep_word(
                    self.sha, method, excludes=self.excludes
                )
                if hits:
                    sample = self._sample_hits(hits)
                    return Finding(
                        claim,
                        Verdict.MISMATCH,
                        f"'{name}' does not appear verbatim at {self.rev}, "
                        f"but '{method}' does ({sample})",
                    )
        if hits:
            sample = self._sample_hits(hits)
            if all(_is_doc_path(h[0]) for h in hits):
                return Finding(
                    claim,
                    Verdict.MISMATCH,
                    f"'{name}' appears only in documentation/text files at "
                    f"{self.rev} ({sample}), never in source code",
                )
            defn = self._definition_hit(name, hits)
            more = "+" if len(hits) >= 50 else ""
            if defn:
                return Finding(
                    claim, Verdict.VERIFIED,
                    f"defined at {defn}; {len(hits)}{more} occurrence(s) "
                    f"at {self.rev}",
                )
            return Finding(
                claim, Verdict.VERIFIED,
                f"{len(hits)}{more} occurrence(s) at {self.rev} ({sample})",
            )
        ci_hits = self.repo.grep_word(
            self.sha, name, ignore_case=True, excludes=self.excludes
        )
        if ci_hits:
            return Finding(
                claim,
                Verdict.MISMATCH,
                f"'{name}' does not appear at {self.rev}, but a "
                f"different-cased spelling does ({self._sample_hits(ci_hits)})",
            )
        return Finding(
            claim,
            Verdict.NOT_FOUND,
            f"identifier appears nowhere in the tree at {self.rev} "
            f"(whole-word search across {len(self._tree)} files)",
        )

    @staticmethod
    def _sample_hits(hits) -> str:
        first = hits[0]
        return f"e.g. {first[0]}:{first[1]}"

    @staticmethod
    def _definition_hit(name: str, hits) -> Optional[str]:
        defn_re = re.compile(
            r"(?:^|\s)(?:def|fn|func|function|sub|class|struct|interface|"
            r"trait|impl)\s+" + re.escape(name) + r"\b"
            r"|^\s*(?:[A-Za-z_][\w\s\*&<>:,]*?[\s\*&])?"
            + re.escape(name) + r"\s*\("
        )
        fallback = None
        for path, line, text in hits:
            if not defn_re.search(text):
                continue
            # Prose in a docs file can look like a definition; only fall
            # back to one when no source file offers a better answer.
            if _is_doc_path(path):
                fallback = fallback or f"{path}:{line}"
                continue
            return f"{path}:{line}"
        return fallback

    # --------------------------------------------------------- STACK_FRAME

    def _verify_stack_frame(self, claim: Claim) -> Finding:
        func = claim.extra["function"]
        path = claim.extra.get("path")
        line = claim.extra.get("line")

        resolved = self._resolve_path(path) if path else None
        func_hits_in_file = (
            self.repo.grep_word(
                self.sha, func, path=resolved, excludes=self.excludes
            )
            if resolved
            else []
        )
        func_hits_anywhere = func_hits_in_file or self.repo.grep_word(
            self.sha, func, excludes=self.excludes
        )
        # A frame claims the function EXECUTED; appearing only in docs is
        # no better than not appearing at all.
        docs_only = bool(func_hits_anywhere) and all(
            _is_doc_path(h[0]) for h in func_hits_anywhere
        )

        problems = []
        goods = []
        if path:
            if resolved:
                goods.append(f"file {resolved} exists")
            elif self._is_external_path(path):
                return Finding(
                    claim, Verdict.UNCHECKABLE,
                    f"frame points into an external/system source file "
                    f"({path}), not this tree",
                )
            else:
                problems.append(f"file {path} not in the tree")
        if docs_only:
            problems.append(
                f"function '{func}' appears only in documentation/text "
                f"files at {self.rev}, never in source code"
            )
        elif func_hits_anywhere:
            where = self._sample_hits(func_hits_anywhere)
            goods.append(f"function '{func}' appears at {self.rev} ({where})")
        else:
            problems.append(
                f"function '{func}' appears nowhere in the tree at {self.rev}"
            )
        if resolved and line:
            count = self.repo.line_count(self.sha, resolved)
            if count is not None and line > count:
                problems.append(
                    f"{resolved} has only {count} lines; frame cites "
                    f"line {line}"
                )
            elif count is not None:
                goods.append(f"line {line} is within {resolved}")
        if resolved and not func_hits_in_file and func_hits_anywhere:
            problems.append(
                f"'{func}' never appears in {resolved} (found elsewhere only)"
            )

        evidence = "; ".join(goods + problems)
        if not problems:
            return Finding(claim, Verdict.VERIFIED, evidence)
        if not func_hits_anywhere and (not path or not resolved):
            return Finding(claim, Verdict.NOT_FOUND, evidence)
        if not func_hits_anywhere:
            return Finding(claim, Verdict.NOT_FOUND, evidence)
        return Finding(claim, Verdict.MISMATCH, evidence)

    @staticmethod
    def _is_external_path(path: str) -> bool:
        markers = (
            "/usr/", "/lib/x86_64", "libc", "glibc", "/sysdeps/",
            "compiler-rt", "libsanitizer", "asan_", "sanitizer_common",
            "interception", "/glibc-", "musl", "crtstuff",
        )
        return any(m in path for m in markers)

    # --------------------------------------------------------- QUOTED_CODE

    def _verify_quoted_code(self, claim: Claim) -> Finding:
        lines: List[str] = claim.extra.get("lines", [])
        hint = claim.extra.get("hint_path")
        origin = claim.extra.get("origin", "quote")
        if len(lines) < 3:
            return Finding(
                claim, Verdict.UNCHECKABLE,
                f"only {len(lines)} distinctive line(s) to sample - too few "
                "to grade fairly",
            )
        found = 0
        example_hit = None
        for needle in lines:
            hits = self.repo.grep_fixed_line(
                self.sha, needle, excludes=self.excludes
            )
            if hits:
                found += 1
                if example_hit is None:
                    example_hit = hits[0]
        ratio = found / len(lines)
        where = (
            f" (e.g. {example_hit[0]}:{example_hit[1]})" if example_hit else ""
        )
        what = "patch context" if origin == "patch" else "quoted code"
        hint_note = f" [report attributes it to {hint}]" if hint else ""
        if ratio >= 0.8:
            return Finding(
                claim, Verdict.VERIFIED,
                f"{found}/{len(lines)} sampled lines of {what} found "
                f"verbatim at {self.rev}{where}{hint_note}",
            )
        if found == 0:
            return Finding(
                claim,
                Verdict.NOT_FOUND,
                f"0/{len(lines)} sampled lines of {what} appear anywhere in "
                f"the tree at {self.rev}{hint_note} - the report quotes code "
                "this codebase does not contain",
            )
        return Finding(
            claim,
            Verdict.MISMATCH,
            f"only {found}/{len(lines)} sampled lines of {what} found at "
            f"{self.rev}{where}{hint_note} - possibly a different version, "
            "or partially invented",
        )

    # -------------------------------------------------------------- VERSION

    def _verify_version(self, claim: Claim) -> Finding:
        tags = self.repo.tags()
        tag_map = self.repo.version_tag_map()
        if len(tag_map) < 2:
            return Finding(
                claim, Verdict.UNCHECKABLE,
                "the repository has too few version-like tags to check "
                "version claims against (shallow or tagless clone? "
                "try `git fetch --tags`)",
            )

        role = claim.extra.get("role", "mentioned")
        if role == "range":
            start, end = claim.extra["start"], claim.extra["end"]
            missing = [v for v in (start, end) if not self._version_known(v, tag_map)]
            inverted = self._version_tuple(start) > self._version_tuple(end)
            if not missing and not inverted:
                return Finding(
                    claim, Verdict.VERIFIED,
                    f"both endpoints match released tags "
                    f"({tag_map.get(_normalize_version_text(start) or start)}"
                    f" .. {tag_map.get(_normalize_version_text(end) or end)})",
                )
            problems = []
            if missing:
                problems.append(
                    f"no release tag matches version(s): {', '.join(missing)} "
                    f"({len(tags)} tags checked)"
                )
            if inverted:
                problems.append("the range is inverted (start > end)")
            verdict = (
                Verdict.NOT_FOUND if len(missing) == 2 else Verdict.MISMATCH
            )
            return Finding(claim, verdict, "; ".join(problems))

        version = claim.value
        if self._version_known(version, tag_map):
            tag = tag_map[_normalize_version_text(version) or version]
            return Finding(
                claim, Verdict.VERIFIED,
                f"matches release tag {tag}",
            )
        near = self._nearest_versions(version, tag_map)
        return Finding(
            claim,
            Verdict.NOT_FOUND,
            f"no release tag matches this version ({len(tags)} tags checked)",
            suggestion=(
                f"nearest real versions: {near}" if near else None
            ),
        )

    @staticmethod
    def _version_known(version: str, tag_map) -> bool:
        norm = _normalize_version_text(version) or version
        return norm in tag_map

    @staticmethod
    def _version_tuple(version: str):
        parts = re.findall(r"\d+", version)
        return tuple(int(p) for p in parts) if parts else (0,)

    def _nearest_versions(self, version: str, tag_map) -> str:
        target = self._version_tuple(version)
        scored = sorted(
            tag_map.keys(),
            key=lambda v: (
                abs(self._version_tuple(v)[0] - target[0]) if target else 0,
                v,
            ),
        )
        return ", ".join(scored[:3])

    # --------------------------------------------------------------- COMMIT

    def _verify_commit(self, claim: Claim) -> Finding:
        info = self.repo.commit_exists(claim.value)
        if info:
            sha, _, subject = info.partition(" ")
            return Finding(
                claim, Verdict.VERIFIED,
                f'resolves to {sha[:12]} ("{subject[:60]}")',
            )
        return Finding(
            claim,
            Verdict.NOT_FOUND,
            "no commit with this hash exists in the repository "
            "(note: shallow clones can hide old history)",
        )

    # ------------------------------------------------------------------ CVE

    def _verify_cve(self, claim: Claim) -> Finding:
        year = claim.extra.get("year", 0)
        this_year = datetime.date.today().year
        if year > this_year:
            return Finding(
                claim,
                Verdict.MISMATCH,
                f"CVE year {year} is in the future",
            )
        if year < 1999:
            return Finding(
                claim, Verdict.MISMATCH,
                f"CVE year {year} predates the CVE program (1999)",
            )
        return Finding(
            claim,
            Verdict.UNCHECKABLE,
            "well-formed identifier; existence in the CVE database is not "
            "checked (vulnvet runs offline)",
        )


def _self_exclusions(report_path: str, repo: Repo) -> List[str]:
    """If the report file sits inside the repo, exclude it from searches:
    a report must never corroborate itself."""
    import os

    if report_path in ("<stdin>", "<api>"):
        return []
    try:
        rel = os.path.relpath(
            os.path.abspath(report_path), os.path.abspath(repo.path)
        )
    except ValueError:  # different drive on Windows
        return []
    if rel.startswith(".."):
        return []
    return [rel.replace(os.sep, "/")]


def build_dossier(
    report_path: str,
    repo: Repo,
    rev_input: Optional[str],
    claims: List[Claim],
    notes: List[str],
) -> Dossier:
    """Resolve the revision, grade every claim, assemble the dossier."""
    run_notes = list(notes)
    if rev_input:
        sha = repo.resolve_rev(rev_input)
        if sha is None:
            raise GitError(
                f"could not resolve --rev '{rev_input}' to a commit "
                f"(tried tag spellings too)"
            )
        rev_name = repo.rev_name(sha)
        if rev_name != rev_input and not sha.startswith(rev_input):
            run_notes.append(f"--rev '{rev_input}' resolved to {rev_name} ({sha[:12]})")
    else:
        sha = repo.resolve_rev("HEAD")
        if sha is None:
            raise GitError("repository has no commits (cannot resolve HEAD)")
        rev_name = repo.rev_name(sha)
        run_notes.append(
            "no --rev given: checking HEAD. If the report names an affected "
            "version, re-run with --rev <version> for a fairer check."
        )

    excludes = _self_exclusions(report_path, repo)
    if excludes:
        run_notes.append(
            f"the report file itself lives inside the repo; "
            f"{excludes[0]} was excluded from corroboration searches"
        )
    verifier = Verifier(repo, sha, display=rev_name, exclude_paths=excludes)
    findings = [verifier.verify(c) for c in claims]
    return Dossier(
        report_path=report_path,
        repo_path=repo.path,
        rev=rev_name,
        rev_sha=sha,
        findings=findings,
        notes=run_notes,
    )
