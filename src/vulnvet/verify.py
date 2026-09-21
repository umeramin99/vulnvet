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
from .extract import POC_FILENAME_RE
from .gitrepo import MAX_GREP_HITS, GitError, Repo, _normalize_version_text


#: Files that are documentation, not source: a symbol living ONLY here
#: was never code the project shipped.
_DOC_EXTS = (".md", ".markdown", ".rst", ".txt", ".adoc", ".textile", ".org")
_DOC_BASENAMES = ("changelog", "changes", "news", "history", "authors", "thanks")


#: Extensions that make a file source, whatever it is named. Without
#: this, a project's real history.c or changes.c would be classified as
#: documentation and its symbols reported as never appearing in code.
_SOURCE_EXTS = (
    ".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx",
    ".inc", ".def", ".tcc", ".ipp", ".py", ".pyx", ".pyi", ".rs", ".go",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".rb", ".php",
    ".swift", ".kt", ".kts", ".cs", ".fs", ".m", ".mm", ".pl", ".pm",
    ".sh", ".bash", ".zsh", ".ps1", ".lua", ".zig", ".scala", ".ex",
    ".exs", ".erl", ".hrl", ".hs", ".dart", ".jl", ".nim", ".r", ".sql",
    ".proto", ".asm", ".s", ".vue", ".svelte", ".clj", ".cljs", ".elm",
    ".ml", ".mli", ".f90", ".f", ".for", ".pas", ".d", ".v", ".sv",
)


#: Build, packaging and CI files. These are not source in the
#: compiler's sense, but build-time injection and workflow script
#: injection are real vulnerability classes, and a report about one
#: cites exactly these files - so a symbol living only here is the
#: subject of the report, not a leftover mention of deleted code.
_BUILD_EXTS = (
    ".cmake", ".mk", ".mak", ".am", ".ac", ".m4", ".bzl", ".bazel",
    ".gradle", ".yml", ".yaml",
)

#: The same files that carry no extension to recognise them by.
_BUILD_BASENAMES = (
    "makefile", "gnumakefile", "cmakelists.txt", "configure",
    "dockerfile", "meson.build", "justfile",
)


def _is_source_path(path: str) -> bool:
    """Does a hit here mean the symbol is in code the project ships?

    Only a recognised source extension counts. Projects keep large
    amounts of extension-less prose in the tree - curl ships RELEASE-NOTES
    and docs/libcurl/symbols-in-versions, an exhaustive list of every
    symbol it has ever had, including deleted ones. Treating those as
    source let removed functions grade VERIFIED and get reported as
    "defined at RELEASE-NOTES:123".

    Build and CI files count as code here: a Makefile recipe or a
    workflow step is what a build-injection report is about.
    """
    lower = path.lower()
    if lower.endswith(_SOURCE_EXTS) or lower.endswith(_BUILD_EXTS):
        return True
    # Makefile, configure and friends have no extension to match on,
    # and CMakeLists.txt has one that reads as prose, so the name
    # itself has to be consulted.
    return lower.rsplit("/", 1)[-1] in _BUILD_BASENAMES


def _is_doc_path(path: str) -> bool:
    """The complement: anything that is not source cannot corroborate."""
    return not _is_source_path(path)


def _only_in_docs(hits: List[Tuple[str, int, str]]) -> bool:
    """True when every hit is a documentation file - and we can say so.

    git grep results are capped, so a full cap's worth of doc hits does
    not prove there is no source hit beyond the cap. Asserting otherwise
    would be a factual claim the evidence does not support.
    """
    if not hits or len(hits) >= MAX_GREP_HITS:
        return False
    return all(_is_doc_path(h[0]) for h in hits)


def _is_bare_document(path: str) -> bool:
    """A directory-less document name, e.g. ``report.md`` or ``notes.txt``.

    ``docs/SECURITY.md`` is a real path claim; a bare ``report.md`` is
    almost always the reporter naming an attachment.
    """
    return "/" not in path and path.lower().endswith(_DOC_EXTS)


def _is_bare_poc_attachment(path: str) -> bool:
    """A directory-less PoC filename, e.g. ``poc.py`` or ``exploit.py``.

    "I have attached poc.py" names the reporter's own script. That is
    not a citation of the codebase, so the tree cannot answer it - and
    the same filenames the extractor already refuses to grade as
    quoted source decide it here.
    """
    return "/" not in path and bool(POC_FILENAME_RE.match(path))


#: Where C preprocessor token pasting can actually occur.
_C_FAMILY_EXTS = (
    ".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx",
    ".inc", ".def", ".tcc", ".ipp", ".m", ".mm",
)

#: "a ## b" joins two tokens; "## Install" is a heading.
_TOKEN_PASTE_RE = re.compile(r"\w\s*##\s*\w")


#: A qualified citation: Engine._run_query, Foo::bar, module.helper.
_QUALIFIER_RE = re.compile(r"(?:::|\.)")


def _split_qualified(name: str):
    """(owner, separator, member) for a qualified symbol citation."""
    for sep in ("::", "."):
        if sep in name:
            head, _, tail = name.rpartition(sep)
            return head, sep, tail
    return "", "", name


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
        #: Build-time directory prefixes this project was compiled under,
        #: learned from stack frames that do resolve into the tree.
        self.build_roots: set = set()
        self._uses_token_pasting: Optional[bool] = None
        self._tree = repo.tree_files(rev)
        self._tree_set = set(self._tree)
        self._basenames: dict = {}
        # Directory suffixes of at least two components. One component is
        # useless as evidence: nearly every project has a "lib" or "src",
        # so a dependency's own lib/ would otherwise read as a claim on us.
        self._dirs = set()
        for path in self._tree:
            self._basenames.setdefault(path.rsplit("/", 1)[-1], []).append(path)
            parts = path.split("/")[:-1]
            for i in range(max(0, len(parts) - 1)):
                self._dirs.add("/".join(parts[i:]))

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
        """The tree path a citation refers to, or None.

        A stack frame carries the absolute path the machine compiled
        under, so ``/src/curl/lib/http.c`` has to resolve to
        ``lib/http.c``. That tolerance cannot extend to arbitrary
        prefixes: ``vendor/quicfork/patched/lib/http2.c`` also ends in a
        real path, and accepting it made the dossier corroborate - and
        quote lines from - a path the repository has never contained.
        A discarded prefix must therefore look like a build location:
        absolute, or a learned build root.
        """
        if path in self._tree_set:
            return path
        stripped = path.lstrip("/")
        if stripped in self._tree_set:
            return stripped

        # The report gave less path than the tree has ("http.c" for
        # "src/http.c"). There is no prefix to fabricate in this
        # direction, so a unique match is safe.
        shorter = [p for p in self._tree if p.endswith("/" + stripped)]
        if len(shorter) == 1:
            return shorter[0]

        # The report gave more path than the tree has. This is the
        # direction a build root explains and an invention abuses.
        longer = [
            p for p in self._tree
            if p != stripped and stripped.endswith("/" + p)
        ]
        if len(longer) != 1:
            return None
        candidate = longer[0]
        prefix = stripped[: -len(candidate)]
        if self._is_build_prefix(path, prefix):
            return candidate
        return None

    def _is_build_prefix(self, original: str, prefix: str) -> bool:
        """Is the discarded prefix plausibly where this was compiled?"""
        if not prefix:
            return True
        normalized = original.replace("\\", "/")
        if any(normalized.startswith(root) for root in self.build_roots):
            return True
        # An absolute path is a build location by construction; a
        # relative one is the reporter describing a tree layout, and a
        # tree layout that is not ours is not ours.
        return normalized.startswith("/")

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

    def _worktree_differs(self) -> bool:
        """Can the checkout hold anything the pinned revision does not?

        Two ways: uncommitted work, or a HEAD that simply is not the
        revision being graded. Gating on dirtiness alone missed the
        second, so a tree several releases ahead of an old --rev was
        never consulted at all.
        """
        head = self.repo.head_sha()
        if head and not (head.startswith(self.sha) or self.sha.startswith(head)):
            return True
        return self.repo.is_dirty()

    def _uncommitted_note(self, kind: str) -> str:
        """Evidence text when the checkout, but not the revision, has it.

        This is the one place vulnvet looks outside the revision it was
        given, and it looks in one direction only: to withdraw a negative
        verdict, never to grant a positive one. A maintainer running this
        on their own checkout usually has uncommitted work - or has it
        sitting on a newer revision than the one being graded - and a
        report describing either is not a fabricated report.
        """
        head = self.repo.head_sha()
        elsewhere = bool(
            head and not (head.startswith(self.sha) or self.sha.startswith(head))
        )
        if elsewhere:
            where = (
                f"present in the checked-out tree, which is at {head[:12]}, "
                f"not {self.rev}"
            )
            reason = "the report may describe a newer revision"
        else:
            where = "present in the working tree"
            reason = "the report may describe uncommitted work"
        return (
            f"{kind} is not committed at {self.rev}, but is {where} - "
            f"{reason}. Re-run with --rev to check a revision that "
            f"contains it."
        )

    def _path_is_uncommitted(self, path: str) -> bool:
        if not self._worktree_differs():
            return False
        if path in self.excludes:
            # The report file itself is never evidence for the report.
            return False
        return self.repo.worktree_has_path(path)

    def _quote_is_uncommitted(self, lines: List[str]) -> bool:
        """Every sampled line on disk, none of them committed yet.

        The same bar a revision has to clear to grade VERIFIED: a
        partial match in the working tree explains nothing and must not
        soften the verdict.
        """
        if not lines or not self._worktree_differs():
            return False
        try:
            return all(
                self.repo.grep_worktree_line(line, excludes=self.excludes)
                for line in lines
            )
        except GitError:
            return False

    def _symbol_is_uncommitted(self, name: str) -> bool:
        if not self._worktree_differs():
            return False
        try:
            return bool(self.repo.grep_worktree(name, excludes=self.excludes))
        except GitError:
            return False

    # ---------------------------------------------------------------- FILE

    def _verify_file(self, claim: Claim) -> Finding:
        path = claim.extra.get("path", claim.value)
        resolved = self._resolve_path(path)
        if resolved is None and self._inside_submodule(path):
            return Finding(
                claim, Verdict.UNCHECKABLE,
                f"path lies inside a submodule, whose contents are not "
                f"stored in this repository at {self.rev}",
            )
        if resolved is None and _is_bare_document(path):
            # "see report.md" / "attached notes.txt" names an attachment,
            # not a path in the tree. Grading it NOT FOUND would be an
            # accusation about the reporter's filing habits.
            return Finding(
                claim, Verdict.UNCHECKABLE,
                "reads as a reference to an attached document rather than a "
                "path in the repository",
            )
        if resolved is None and _is_bare_poc_attachment(path):
            return Finding(
                claim, Verdict.UNCHECKABLE,
                "reads as a reference to an attached file - the reporter's "
                "own proof of concept - rather than a path in the repository",
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
        if self._path_is_uncommitted(path):
            return Finding(
                claim, Verdict.MISMATCH, self._uncommitted_note("this file"),
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
        if not resolved and self._inside_submodule(path):
            return Finding(
                claim, Verdict.UNCHECKABLE,
                f"path lies inside a submodule, whose contents are not "
                f"stored in this repository at {self.rev}",
            )
        # A line number does not turn an attachment into a repository path:
        # "poc.py:42" is still the reporter's own file. _verify_file already
        # declines to grade these, and disagreeing with it inside one dossier
        # would be worse than either answer alone.
        if not resolved and _is_bare_document(path):
            return Finding(
                claim, Verdict.UNCHECKABLE,
                "reads as a reference to an attached document rather than a "
                "path in the repository",
            )
        if not resolved and _is_bare_poc_attachment(path):
            return Finding(
                claim, Verdict.UNCHECKABLE,
                "reads as a reference to an attached file - the reporter's "
                "own proof of concept - rather than a path in the repository",
            )
        if not resolved:
            suggested = self._suggest_path(path)
            if suggested and suggested[1]:
                return Finding(
                    claim,
                    Verdict.MISMATCH,
                    f"no file at this path at {self.rev}",
                    suggestion=f"did the reporter mean {suggested[0]}?",
                )
            if self._path_is_uncommitted(path):
                return Finding(
                    claim, Verdict.MISMATCH,
                    self._uncommitted_note("this file"),
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
        # A cited range asserts both ends. Checking only the start let
        # "src/http.c:1-9000" grade VERIFIED against an eight-line file.
        end = claim.extra.get("end_line")
        cited = f"lines {line}-{end}" if end else f"line {line}"
        beyond = max(line, end or line)
        if beyond > count:
            which = (
                f"the report cites {cited}"
                if end
                else f"the report cites line {line}"
            )
            return Finding(
                claim,
                Verdict.MISMATCH,
                f"{resolved} exists but has only {count} lines at "
                f"{self.rev}; {which}",
            )
        text = self.repo.line_at(self.sha, resolved, line) or ""
        snippet = text.strip()[:80]
        where = f"{resolved}:{line}-{end}" if end else f"{resolved}:{line}"
        opening = " - opens: " if end else " - reads: "
        return Finding(
            claim, Verdict.VERIFIED,
            f"{where} exists at {self.rev}"
            + (f'{opening}"{snippet}"' if snippet else " (blank line)"),
        )

    def _verify_qualified(self, claim, name, head, tail, tail_hits) -> Finding:
        """Grade ``Head.tail`` when the tail exists but the joined form cannot.

        The question a maintainer needs answered is whether the method the
        report names is real and lives where the report implies. That is
        what the evidence says here - never that the citation "appears
        nowhere in the tree", which is false and reads as a fabrication.
        """
        attributed = claim.extra.get("in_file")
        resolved = self._resolve_path(attributed) if attributed else None
        if resolved:
            # The report said "Head.tail in Y": ask git about Y directly
            # rather than filtering capped results.
            in_file = self.repo.grep_word(
                self.sha, tail, path=resolved, excludes=self.excludes
            )
            if not in_file:
                best = self._best_hit(tail_hits)
                return Finding(
                    claim, Verdict.MISMATCH,
                    f"'{tail}' exists at {self.rev} (e.g. "
                    f"{best[0]}:{best[1]}) but never appears in {resolved}, "
                    f"where the report places '{name}'",
                    suggestion=f"the report may mean {best[0]}",
                )
            tail_hits = in_file

        if _only_in_docs(tail_hits):
            return Finding(
                claim, Verdict.MISMATCH,
                f"'{tail}' appears at {self.rev} only outside source code "
                f"({self._sample_hits(tail_hits)}) - in documentation, "
                f"release notes or other non-source files, which is where a "
                f"removed member still gets mentioned",
            )

        defn = self._definition_hit(tail, tail_hits)
        best = self._best_hit(tail_hits)
        where = defn or f"{best[0]}:{best[1]}"
        tail_file = where.rsplit(":", 1)[0]
        shown = "is defined at" if defn else "appears at"
        spelling = (
            f"the qualified spelling '{name}' is how a caller writes it, "
            f"not how the source declares it"
        )

        # A one- or two-character owner is a local variable, not a type:
        # "s.read" says nothing checkable about "s".
        if len(head) < 3:
            return Finding(
                claim, Verdict.VERIFIED,
                f"'{tail}' {shown} {where} at {self.rev}; {spelling}",
            )

        # Does the owner appear alongside its member? That is as much as a
        # text search can honestly say about Head.tail, and it is enough to
        # tell a real citation from an invented one.
        head_here = self.repo.grep_word(
            self.sha, head, path=tail_file, excludes=self.excludes
        )
        if head_here:
            return Finding(
                claim, Verdict.VERIFIED,
                f"'{tail}' {shown} {where}, in the same file as '{head}' - "
                f"{spelling}",
            )
        head_anywhere = self.repo.grep_word(
            self.sha, head, excludes=self.excludes
        )
        if head_anywhere:
            return Finding(
                claim, Verdict.MISMATCH,
                f"'{tail}' {shown} {where}, and '{head}' exists at "
                f"{self._sample_hits(head_anywhere)}, but not in the same "
                f"file - the member may be attributed to the wrong owner",
                suggestion=f"'{tail}' lives in {tail_file}",
            )
        return Finding(
            claim, Verdict.MISMATCH,
            f"'{tail}' {shown} {where}, but '{head}' appears nowhere at "
            f"{self.rev} - the member is real, its stated owner is not",
        )

    # -------------------------------------------------------------- SYMBOL

    def _verify_symbol(self, claim: Claim) -> Finding:
        name = claim.value
        hits = self.repo.grep_word(self.sha, name, excludes=self.excludes)
        attributed = claim.extra.get("in_file")
        if not hits and attributed and self._inside_submodule(attributed):
            return Finding(
                claim, Verdict.UNCHECKABLE,
                f"the report places this symbol in {attributed}, which lies "
                f"inside a submodule whose contents are not stored in this "
                f"repository at {self.rev}",
            )
        if attributed and hits:
            # The report said "X in file Y". A real symbol cited in a file
            # it does not live in is a distinct, checkable error that
            # grading the symbol and the file separately would miss.
            resolved = self._resolve_path(attributed)
            if resolved:
                # Ask git about that file directly. Filtering the general
                # search would be wrong: its results are capped, so a
                # common identifier's hits in the cited file can fall off
                # the end and look like an absence.
                in_file = self.repo.grep_word(
                    self.sha, name, path=resolved, excludes=self.excludes
                )
                if not in_file:
                    defn = self._definition_hit(name, hits)
                    best = self._best_hit(hits)
                    where = defn or f"{best[0]}:{best[1]}"
                    return Finding(
                        claim,
                        Verdict.MISMATCH,
                        f"'{name}' exists at {self.rev} "
                        f"({'defined at ' if defn else 'e.g. '}{where}) but "
                        f"never appears in {resolved}, where the report "
                        f"places it",
                        suggestion=(
                            f"the report may mean {where.rsplit(':', 1)[0]}"
                        ),
                    )
                hits = in_file
        if not hits and _QUALIFIER_RE.search(name):
            # A qualified name - Engine._run_query, Foo::bar, mod.helper -
            # is how Python, Java, JavaScript, Ruby and C++ reports cite a
            # method, and it is NEVER the literal text of the source: the
            # call site reads self._run_query(...). Grading the whole
            # string as one identifier reported the commonest correct
            # citation in most languages as a fabrication.
            head, _, tail = _split_qualified(name)
            if len(tail) >= 3:
                tail_hits = self.repo.grep_word(
                    self.sha, tail, excludes=self.excludes
                )
                if tail_hits:
                    return self._verify_qualified(claim, name, head, tail,
                                                  tail_hits)
        if hits:
            sample = self._sample_hits(hits)
            if _only_in_docs(hits):
                return Finding(
                    claim,
                    Verdict.MISMATCH,
                    f"'{name}' appears at {self.rev} only outside source "
                    f"code ({sample}) - in documentation, release notes or "
                    f"other non-source files, which is where a removed "
                    f"function still gets mentioned",
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
        evidence = (
            f"identifier appears nowhere in the tree at {self.rev} "
            f"(whole-word search across {len(self._tree)} files)"
        )
        if self._symbol_is_uncommitted(name):
            return Finding(
                claim, Verdict.MISMATCH,
                self._uncommitted_note(f"'{name}'"),
            )
        return Finding(
            claim, Verdict.NOT_FOUND, evidence,
            suggestion=self._token_paste_caveat(),
        )

    @classmethod
    def _sample_hits(cls, hits) -> str:
        best = cls._best_hit(hits)
        return f"e.g. {best[0]}:{best[1]}"

    @staticmethod
    def _best_hit(hits):
        """The most useful hit to show a maintainer: source over docs."""
        for hit in hits:
            if not _is_doc_path(hit[0]):
                return hit
        return hits[0]

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
            # "    foo_bar(x);" is a call, not a definition. Definitions
            # continue onto a body rather than ending the statement.
            if text.rstrip().endswith(";"):
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
        unqualified = None
        if not func_hits_anywhere and "::" in func:
            # Traces print qualified C++ names; the source declares the
            # method unqualified inside its class.
            candidate = func.rsplit("::", 1)[-1]
            if len(candidate) >= 4:
                hits = self.repo.grep_word(
                    self.sha, candidate, excludes=self.excludes
                )
                if hits:
                    unqualified = candidate
                    func_hits_anywhere = hits
                    if resolved:
                        func_hits_in_file = self.repo.grep_word(
                            self.sha, candidate, path=resolved,
                            excludes=self.excludes,
                        )
        # A frame claims the function EXECUTED; appearing only in docs is
        # no better than not appearing at all.
        docs_only = _only_in_docs(func_hits_anywhere)

        # A stack trace walks through whatever code was linked in, so most
        # frames legitimately name files this repository has never
        # contained. vulnvet can only speak to this tree, so a frame is
        # graded only when it claims to be inside it. Note that the
        # function merely appearing here is not such a claim: curl calls
        # nghttp2_session_mem_recv(), but a frame inside nghttp2's own
        # source is still nghttp2's frame, not curl's.
        if path and not resolved:
            if self._is_external_path(path):
                return Finding(
                    claim, Verdict.UNCHECKABLE,
                    f"frame points into an external/system source file "
                    f"({path}), not this tree",
                )
            if not self._frame_claims_this_tree(path):
                return Finding(
                    claim, Verdict.UNCHECKABLE,
                    f"frame names a file outside this tree "
                    f"({path}) whose directory does not correspond to any "
                    f"in the repository at {self.rev} - most likely a "
                    f"dependency or system library vulnvet cannot see",
                )
        if not path and not func_hits_anywhere:
            # No file to anchor on and a name we do not have: this could
            # be a fabrication or a frame from any linked library. Say so
            # rather than guess.
            return Finding(
                claim, Verdict.UNCHECKABLE,
                f"function '{func}' does not appear in this tree at "
                f"{self.rev} and the frame names no file, so it cannot be "
                f"told apart from a frame in a dependency",
            )

        problems = []
        goods = []
        if path:
            if resolved:
                goods.append(f"file {resolved} exists")
            else:
                problems.append(f"file {path} not in the tree")
        if docs_only:
            problems.append(
                f"function '{func}' appears only in documentation/text "
                f"files at {self.rev}, never in source code"
            )
        elif func_hits_anywhere:
            where = self._sample_hits(func_hits_anywhere)
            shown = (
                f"'{func}' (as unqualified '{unqualified}')"
                if unqualified
                else f"function '{func}'"
            )
            goods.append(f"{shown} appears at {self.rev} ({where})")
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
        if not func_hits_anywhere:
            # A backtrace is the commonest way a real reporter names a
            # function, and STACK_FRAME feeds the strong-signal count.
            # Without this, the exact regression the working-tree check
            # exists to prevent still fired for anyone whose crash was
            # in code they had not committed.
            if self._symbol_is_uncommitted(func):
                return Finding(
                    claim, Verdict.MISMATCH,
                    self._uncommitted_note(f"function '{func}'"),
                )
            return Finding(claim, Verdict.NOT_FOUND, evidence)
        return Finding(claim, Verdict.MISMATCH, evidence)

    def _inside_submodule(self, path: str) -> bool:
        stripped = path.lstrip("/")
        for sub in self.repo.submodule_paths(self.sha):
            if stripped == sub or stripped.startswith(sub + "/"):
                return True
            if ("/" + stripped).endswith("/" + sub) or f"/{sub}/" in f"/{stripped}":
                return True
        return False

    def learn_build_roots(self, frame_paths) -> None:
        """Infer where this project was compiled, from frames that resolve.

        A trace's frames carry absolute build paths. The ones that land in
        this tree reveal the prefix the project was built under - given
        ``/home/build/curl/lib/http2.c`` resolving to ``lib/http2.c``, the
        root is ``/home/build/curl/``. Any other frame sharing that root
        is this project's code; a frame under ``/home/build/openssl/`` is
        not, however similar the two look.
        """
        for path in frame_paths:
            if not path:
                continue
            resolved = self._resolve_path(path)
            if not resolved:
                continue
            normalized = path.replace("\\", "/")
            if normalized.endswith(resolved):
                root = normalized[: -len(resolved)]
                if root not in ("", "/"):
                    self.build_roots.add(root)

    def _frame_claims_this_tree(self, path: Optional[str]) -> bool:
        """Does this frame's path assert that it is inside this project?"""
        if not path:
            return False
        normalized = path.replace("\\", "/")
        if any(normalized.startswith(root) for root in self.build_roots):
            return True
        # Without a learned build root, fall back to structural evidence:
        # a directory suffix of two or more components that this tree
        # really has (curl's "lib/vquic"), or a file of the same name.
        # One component is worthless - nearly every project has a "lib".
        parts = normalized.strip("/").split("/")[:-1]
        for i in range(max(0, len(parts) - 1)):
            if "/".join(parts[i:]) in self._dirs:
                return True
        return normalized.rsplit("/", 1)[-1] in self._basenames

    #: Path components that mark a frame as belonging to the system or
    #: to a sanitizer runtime rather than to any project source.
    _EXTERNAL_COMPONENTS = frozenset(
        {
            "usr", "sysdeps", "compiler-rt", "libsanitizer",
            "sanitizer_common", "interception", "crtstuff", "musl",
            "libc", "glibc", "libstdc++", "libc++",
        }
    )

    @classmethod
    def _is_external_path(cls, path: str) -> bool:
        """Is this frame in libc or a sanitizer runtime?

        Matched on whole path components. A substring test called
        /build/libcurl/... external because "libc" is inside "libcurl",
        which dismissed every fabricated frame in a curl report before it
        could be graded.
        """
        for part in path.replace("\\", "/").split("/"):
            if not part:
                continue
            lowered = part.lower()
            if lowered in cls._EXTERNAL_COMPONENTS:
                return True
            # versioned spellings: glibc-2.36, musl-1.2.4
            base = lowered.split("-", 1)[0]
            if base in ("glibc", "musl", "libc") and base != lowered:
                return True
            if lowered.startswith(("asan_", "tsan_", "msan_", "ubsan_")):
                return True
        return "/lib/x86_64" in path

    # --------------------------------------------------------- QUOTED_CODE

    def _verify_quoted_code(self, claim: Claim) -> Finding:
        lines: List[str] = claim.extra.get("lines", [])
        hint = claim.extra.get("hint_path")
        origin = claim.extra.get("origin", "quote")
        if origin == "ambiguous":
            return Finding(
                claim, Verdict.UNCHECKABLE,
                "the surrounding text describes this block both as a quote "
                "from the codebase and as the reporter's own code, so it "
                "was not graded either way - read it yourself",
            )
        if len(lines) < 3:
            return Finding(
                claim, Verdict.UNCHECKABLE,
                f"only {len(lines)} distinctive line(s) to sample - too few "
                "to grade fairly",
            )
        found = 0
        example_hit = None
        missing: List[str] = []
        for needle in lines:
            hits = self.repo.grep_fixed_line(
                self.sha, needle, excludes=self.excludes
            )
            if hits:
                found += 1
                if example_hit is None:
                    example_hit = hits[0]
            else:
                missing.append(needle)
        ratio = found / len(lines)
        # Name what did not match. A ratio alone hides the one inserted
        # line in an otherwise genuine excerpt, which is precisely where
        # a fabricated vulnerability lives.
        missing_note = ""
        if missing:
            shown = "; ".join(m[:70] for m in missing[:3])
            more = f" (+{len(missing) - 3} more)" if len(missing) > 3 else ""
            missing_note = f" Not found in the tree: {shown}{more}."
        where = (
            f" (e.g. {example_hit[0]}:{example_hit[1]})" if example_hit else ""
        )
        what = "patch context" if origin == "patch" else "quoted code"
        hint_note = f" [report attributes it to {hint}]" if hint else ""
        if found == len(lines):
            return Finding(
                claim, Verdict.VERIFIED,
                f"all {found} sampled lines of {what} found verbatim at "
                f"{self.rev}{where}{hint_note}",
            )
        # Anything short of every line is a mismatch that names the gap.
        # A tolerance here is a free line of fabricated code inside an
        # otherwise real excerpt.
        if ratio >= 0.8:
            return Finding(
                claim,
                Verdict.MISMATCH,
                f"{found}/{len(lines)} sampled lines of {what} found at "
                f"{self.rev}{where}{hint_note}.{missing_note}",
            )
        if found == 0:
            if self._quote_is_uncommitted(lines):
                return Finding(
                    claim, Verdict.MISMATCH,
                    self._uncommitted_note(f"this {what}"),
                )
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
            f"or partially invented.{missing_note}",
        )

    # -------------------------------------------------------------- VERSION

    def _verify_version(self, claim: Claim) -> Finding:
        tags = self.repo.tags()
        tag_map = self.repo.version_tag_map()
        if not tag_map:
            return Finding(
                claim, Verdict.UNCHECKABLE, self._tag_shortfall(),
            )

        product = claim.extra.get("product")
        if product and not self._names_this_project(product):
            return Finding(
                claim, Verdict.UNCHECKABLE,
                f"the report attributes this version to {product.strip()}, "
                f"not to this project - vulnvet only knows this "
                f"repository's release tags",
            )

        role = claim.extra.get("role", "mentioned")
        if role == "range":
            start, end = claim.extra["start"], claim.extra["end"]
            missing = [
                v for v in (start, end)
                if not self._version_known(v, tag_map)
                and not self._series_tags(v, tag_map)
            ]
            inverted = self._version_tuple(start) > self._version_tuple(end)
            if not missing and not inverted:
                return Finding(
                    claim, Verdict.VERIFIED,
                    f"both endpoints match released tags "
                    f"({self._tag_for(start, tag_map)}"
                    f" .. {self._tag_for(end, tag_map)})",
                )
            problems = []
            if missing:
                problems.append(
                    f"no release tag matches version(s): {', '.join(missing)} "
                    f"({len(tags)} tags checked)"
                )
            if inverted:
                problems.append("the range is inverted (start > end)")
            if missing and len(tag_map) < 2:
                return Finding(
                    claim, Verdict.UNCHECKABLE, self._tag_shortfall(),
                )
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
        series = self._series_tags(version, tag_map)
        if series:
            return Finding(
                claim, Verdict.VERIFIED,
                f"names a released series rather than a single tag "
                f"({', '.join(series)})",
            )
        if len(tag_map) < 2:
            # One tag cannot distinguish an invented version from one
            # this clone simply never fetched. The exact-match path
            # above still grades VERIFIED - a first release, or the
            # single-tag clone the quickstart makes, is not a reason to
            # refuse the claim it does match.
            return Finding(
                claim, Verdict.UNCHECKABLE, self._tag_shortfall(),
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

    def _tag_shortfall(self) -> str:
        """Why a version cannot be checked here - and what would fix it.

        One message for three situations blamed a "shallow or tagless
        clone" for a complete checkout of a project at its first
        release, and offered `git fetch --tags` to someone for whom it
        does nothing.
        """
        if self.repo.is_shallow():
            return (
                "this clone is shallow, so most tags are missing - run "
                "`git fetch --unshallow --tags` before treating any "
                "version verdict as evidence"
            )
        if not self.repo.tags():
            return (
                "this repository has no tags at all, so there is nothing "
                "to match a version against"
            )
        return (
            f"this repository has only "
            f"{_plural(len(self.repo.version_tag_map()), 'version-like tag')}"
            f" - too few to tell a wrong version from one this clone never "
            f"fetched (`git fetch --tags` if it is partial)"
        )

    def _token_paste_caveat(self) -> Optional[str]:
        """Warn when this project could construct the name at compile time.

        A codebase using ## builds identifiers that never appear literally
        in any file, so a grep miss is weaker evidence than it looks.
        """
        if self._uses_token_pasting is None:
            # "##" alone matches every Markdown heading in every
            # repository, so nearly every project - vulnvet's own
            # included - was told its missing symbols might be
            # preprocessor-generated. Token pasting is a C construct
            # that joins two tokens, so require both: a C-family file,
            # and a paste-shaped context.
            hits = self.repo.grep_fixed_line(
                self.sha, "##", excludes=self.excludes
            )
            self._uses_token_pasting = any(
                path.lower().endswith(_C_FAMILY_EXTS)
                and _TOKEN_PASTE_RE.search(text)
                for path, _, text in hits
            )
        if not self._uses_token_pasting:
            return None
        return (
            "this project uses preprocessor token pasting (##), which can "
            "build identifiers that never appear literally in the source - "
            "check by hand before treating this as invented"
        )

    def _names_this_project(self, product: str) -> bool:
        return _names_this_project(product, self.repo.path)

    @staticmethod
    def _version_known(version: str, tag_map) -> bool:
        norm = _normalize_version_text(version) or version
        return norm in tag_map

    @classmethod
    def _tag_for(cls, version: str, tag_map) -> str:
        """The tag(s) to name in evidence for a version the repo has."""
        exact = tag_map.get(_normalize_version_text(version) or version)
        if exact:
            return exact
        return ", ".join(cls._series_tags(version, tag_map)) or version

    @staticmethod
    def _series_tags(version: str, tag_map) -> List[str]:
        """Tags in the release series a shorter version names.

        "affects version 1.0" is how people refer to the 1.0 line; the
        tag is v1.0.0. Reporting that no release matches would accuse
        an honest reporter over a convention. The prefix has to end on
        a component boundary, so 1.0 does not reach 1.10.2.
        """
        # Not the "or version" fallback the exact check uses: a string
        # with no dotted core names no series, and "1" must not prefix
        # every 1.x tag in the repository.
        norm = _normalize_version_text(version)
        if not norm:
            return []
        return sorted(
            tag for released, tag in tag_map.items()
            if released.startswith(norm + ".")
        )

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


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _unresolvable_rev_message(rev_input: str, repo: Repo) -> str:
    """Say which of the three reasons a revision did not resolve.

    One dead-end sentence for "you typed it wrong", "your clone is
    shallow" and "this project does not tag" left a first-time user with
    nothing to try.
    """
    head = f"could not resolve --rev '{rev_input}' to a commit"
    if repo.is_shallow():
        return (
            f"{head}: this clone is shallow, so most tags and commits are "
            f"missing - try `git fetch --unshallow --tags`"
        )
    tags = repo.tags()
    if not tags:
        return (
            f"{head}: this repository has no tags at all - pass a branch "
            f"name or a commit sha instead, or `git fetch --tags` if the "
            f"clone is partial"
        )
    tag_map = repo.version_tag_map()
    norm = _normalize_version_text(rev_input)
    if norm and tag_map:
        near = sorted(
            tag_map.items(),
            key=lambda kv: difflib.SequenceMatcher(
                None, norm, kv[0]
            ).ratio(),
            reverse=True,
        )[:3]
        spellings = ", ".join(tag for _, tag in near)
        return (
            f"{head}: no tag matches that version. This repository spells "
            f"its releases {spellings} ({_plural(len(tags), 'tag')}; "
            f"`git tag -l` lists them)"
        )
    return (
        f"{head} (tried tag spellings too). `git tag -l` lists the "
        f"{_plural(len(tags), 'tag')} this repository has"
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


def _suggested_rev(
    claims: List[Claim], repo: Repo, current_sha: Optional[str] = None,
) -> Optional[str]:
    """A version the report names that this repository actually has.

    Telling someone to "re-run with --rev <version>" when the report is
    sitting right there naming one is a step the tool can take itself.
    Only a version with a matching tag is offered, so the suggestion
    never sends anyone after a revision that does not exist - nor back
    to the revision they just graded.
    """
    preferred = ("affected", "range", "introduced", "mentioned",
                 "before", "fixed")
    #: Roles that name the boundary the bug was fixed at, not a version
    #: that has it. Grading a report against the release that fixed it
    #: is how a truthful report gets a page of NOT FOUND verdicts, so
    #: the release before it is what gets offered.
    exclusive = ("before", "fixed")
    tag_map = repo.version_tag_map()
    candidates: List[str] = []
    for role in preferred:
        for claim in claims:
            if claim.type is not ClaimType.VERSION:
                continue
            if claim.extra.get("role") != role:
                continue
            product = claim.extra.get("product")
            # "affects Ubuntu 22.04" is not ours to check - but "affects
            # curl 8.4.0" names this project as plainly as a report can,
            # and discarding it for carrying a product word at all threw
            # away the most explicit statement in the report.
            if product and not _names_this_project(product, repo.path):
                continue
            if role == "range":
                # Both ends are worth trying. Collapsing to the end
                # alone dropped a real lower bound whenever the upper
                # one was not a release this repository has.
                values = [claim.extra.get("end"), claim.extra.get("start")]
            else:
                values = [claim.value]
            for value in values:
                if not value:
                    continue
                if role in exclusive:
                    value = _last_release_before(repo, value)
                if value and value not in candidates:
                    candidates.append(value)
    for value in candidates:
        # The tag list is already in memory; asking git first cost two
        # or three processes per version for a question a dict answers.
        if (_normalize_version_text(value) or value) not in tag_map:
            continue
        sha = repo.resolve_rev(value)
        if sha and sha != current_sha:
            return value
    return None


def _names_this_project(product: str, repo_path: str) -> bool:
    """Is this word the project itself rather than a third party?"""
    import os

    word = product.strip().strip(",;:").lower()
    repo_name = os.path.basename(os.path.abspath(repo_path)).lower()
    return word in (repo_name, repo_name.replace("-", ""), "project")


def _last_release_before(repo: Repo, version: str) -> Optional[str]:
    """The newest released version strictly below *version*.

    "fixed in 1.2.0" and "affects everything prior to 1.2.0" both name a
    release that does not contain the bug. The last one that does is the
    tag immediately below it.
    """
    target = _version_sort_key(version)
    if not target:
        return None
    best: Optional[Tuple[tuple, str]] = None
    for released in repo.version_tag_map():
        key = _version_sort_key(released)
        if key and key < target and (best is None or key > best[0]):
            best = (key, released)
    return best[1] if best else None


def _version_sort_key(version: str) -> tuple:
    return tuple(int(p) for p in re.findall(r"\d+", version))


def build_dossier(
    report_path: str,
    repo: Repo,
    rev_input: Optional[str],
    claims: List[Claim],
    notes: List[str],
    dropped: Optional[dict] = None,
) -> Dossier:
    """Resolve the revision, grade every claim, assemble the dossier."""
    run_notes = list(notes)
    if rev_input:
        sha = repo.resolve_rev(rev_input)
        if sha is None:
            raise GitError(_unresolvable_rev_message(rev_input, repo))
        rev_name = repo.rev_name(sha)
        if rev_name != rev_input and not sha.startswith(rev_input):
            run_notes.append(f"--rev '{rev_input}' resolved to {rev_name} ({sha[:12]})")
    else:
        sha = repo.resolve_rev("HEAD")
        if sha is None:
            raise GitError("repository has no commits (cannot resolve HEAD)")
        rev_name = repo.rev_name(sha)
        suggestion = _suggested_rev(claims, repo, current_sha=sha)
        if suggestion:
            run_notes.append(
                f"no --rev given, so this checked HEAD. The report itself "
                f"names version {suggestion}, which exists in this "
                f"repository: re-run with --rev {suggestion} to grade it "
                f"against the code the reporter says they looked at."
            )
        else:
            run_notes.append(
                "no --rev given: checking HEAD. If the report names an "
                "affected version, re-run with --rev <version> for a "
                "fairer check."
            )

    if repo.is_dirty():
        run_notes.append(
            "the checkout has uncommitted changes; claims are graded "
            "against the committed revision, and anything the report "
            "describes that is only in the working tree is reported as "
            "such rather than as missing."
        )
    if getattr(repo, "subdir", ""):
        run_notes.append(
            f"--repo pointed at the subdirectory {repo.subdir}; claims were "
            f"checked against the whole repository"
        )

    excludes = _self_exclusions(report_path, repo)
    if excludes:
        run_notes.append(
            f"the report file itself lives inside the repo; "
            f"{excludes[0]} was excluded from corroboration searches"
        )
    verifier = Verifier(repo, sha, display=rev_name, exclude_paths=excludes)
    verifier.learn_build_roots(
        c.extra.get("path")
        for c in claims
        if c.type is ClaimType.STACK_FRAME
    )
    findings = [verifier.verify(c) for c in claims]
    return Dossier(
        report_path=report_path,
        repo_path=repo.path,
        rev=rev_name,
        rev_sha=sha,
        findings=findings,
        notes=run_notes,
        dropped=dict(dropped or {}),
    )
