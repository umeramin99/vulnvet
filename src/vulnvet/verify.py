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

    def _uncommitted_note(self, kind: str) -> Optional[str]:
        """Evidence text when the working tree, but not the revision, has it.

        This is the one place vulnvet looks outside the revision it was
        given, and it looks in one direction only: to withdraw a negative
        verdict, never to grant a positive one. A maintainer running this
        on their own checkout usually has uncommitted work, and a report
        describing that work is not a fabricated report.
        """
        return (
            f"{kind} is not committed at {self.rev}, but is present in the "
            f"working tree - the report may describe uncommitted work. "
            f"Re-run with --rev to check a revision that contains it."
        )

    def _path_is_uncommitted(self, path: str) -> bool:
        if not self.repo.is_dirty():
            return False
        return self.repo.worktree_has_path(path)

    def _symbol_is_uncommitted(self, name: str) -> bool:
        if not self.repo.is_dirty():
            return False
        try:
            return bool(self.repo.grep_worktree(name))
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
        if len(tag_map) < 2:
            return Finding(
                claim, Verdict.UNCHECKABLE,
                "the repository has too few version-like tags to check "
                "version claims against (shallow or tagless clone? "
                "try `git fetch --tags`)",
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
        near = self._nearest_versions(version, tag_map)
        return Finding(
            claim,
            Verdict.NOT_FOUND,
            f"no release tag matches this version ({len(tags)} tags checked)",
            suggestion=(
                f"nearest real versions: {near}" if near else None
            ),
        )

    def _token_paste_caveat(self) -> Optional[str]:
        """Warn when this project could construct the name at compile time.

        A codebase using ## builds identifiers that never appear literally
        in any file, so a grep miss is weaker evidence than it looks.
        """
        if self._uses_token_pasting is None:
            self._uses_token_pasting = bool(
                self.repo.grep_fixed_line(self.sha, "##", excludes=self.excludes)
            )
        if not self._uses_token_pasting:
            return None
        return (
            "this project uses preprocessor token pasting (##), which can "
            "build identifiers that never appear literally in the source - "
            "check by hand before treating this as invented"
        )

    def _names_this_project(self, product: str) -> bool:
        """Is this word the project itself rather than a third party?"""
        import os

        word = product.strip().strip(",;:").lower()
        repo_name = os.path.basename(os.path.abspath(self.repo.path)).lower()
        return word in (repo_name, repo_name.replace("-", ""), "project")

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
    dropped: Optional[dict] = None,
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
