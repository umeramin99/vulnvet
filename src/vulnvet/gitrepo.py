"""A thin, defensive wrapper around the git CLI.

Everything vulnvet knows about the codebase flows through here. All
lookups are pinned to a single resolved revision so the dossier answers
one precise question: "was this claim true of the tree the reporter says
they looked at?"

No third-party dependencies; plain ``git`` subprocess calls. Patterns
are always passed with ``-e`` / ``--`` separation so report-controlled
strings can never be parsed as git options.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple


class GitError(RuntimeError):
    pass


class NotARepository(GitError):
    pass


#: Cap on grep hits we bother collecting for any single query.
MAX_GREP_HITS = 50

#: Longest search string we will hand to git. A needle comes straight
#: from the report, and the kernel rejects the whole exec once a single
#: argv element passes its limit (E2BIG, ~128 KB). 8192 characters stays
#: four times clear of that even for astral text, so a pasted minified
#: line never reaches the boundary in the first place.
MAX_NEEDLE_CHARS = 8192

#: Bounds on the per-repository blob cache. One file is read several
#: times over a dossier - its line count, then a cited line, then the
#: next claim in it - and every miss is another `git show` process. The
#: character budget keeps a report citing many large files from holding
#: the tree in memory.
MAX_BLOB_CACHE = 64
MAX_BLOB_CACHE_CHARS = 4_000_000


def _normalize_version_text(text: str) -> str:
    """Reduce a tag or version string to a comparable dotted core.

    ``curl-8_9_0`` -> ``8.9.0``; ``v1.2.3`` -> ``1.2.3``; ``rel/2.1`` ->
    ``2.1``. Returns "" when there is nothing version-like inside.
    """
    if not text:
        return ""
    match = re.search(r"(\d+(?:[._-]\d+)+[a-z]?)$", text.strip())
    if not match:
        return ""
    return match.group(1).replace("_", ".").replace("-", ".")


def _prepare_needle(needle: str) -> str:
    """Make a report-supplied search string safe to hand to execve.

    A NUL byte cannot survive in an argv element at all, and a single
    element past the kernel's limit fails the whole exec. Dropping the
    NUL costs nothing - it could not occur in a line ``git grep -I``
    would match either, so the search only becomes more likely to
    corroborate the reporter. An over-long needle is refused rather than
    truncated: a verdict reached on a prefix nobody quoted would be an
    accusation dressed up as a check, and GitError grades the claim
    UNCHECKABLE instead.
    """
    needle = needle.replace("\0", "")
    if len(needle) > MAX_NEEDLE_CHARS:
        raise GitError(
            f"the report quotes a {len(needle)}-character search term, past "
            f"the {MAX_NEEDLE_CHARS}-character limit git can be given"
        )
    return needle


class Repo:
    def __init__(self, path: str):
        # The shell expands "~" for --repo; nothing expands it for a
        # caller passing repo_path="~/src/curl" to the library, and git
        # is spawned without a shell, so the tilde reached git verbatim
        # and the documented example could not run.
        self.path = os.path.expanduser(path)
        self._tree_cache: Dict[str, List[str]] = {}
        self._submodule_cache: Dict[str, List[str]] = {}
        # Keyed on (rev, path) and held on the instance, so it can neither
        # answer for the wrong revision nor leak between repositories.
        self._blob_cache: Dict[Tuple[str, str], Optional[str]] = {}
        self._blob_chars = 0
        self._tags: Optional[List[str]] = None
        self._dirty: Optional[bool] = None
        self._head: Optional[str] = None
        self._worktree_files: Optional[set] = None
        self._shallow: Optional[bool] = None
        self._rev_cache: Dict[str, Optional[str]] = {}
        try:
            out = self._run("rev-parse", "--is-inside-work-tree")
        except GitError as exc:
            raise NotARepository(
                f"{path} is not a git repository (or git is not installed): {exc}"
            ) from exc
        if out.strip() != "true":
            raise NotARepository(f"{path} is not inside a git work tree")
        # git grep scopes to the current directory but ls-tree does not,
        # so a --repo pointing into a subdirectory would make the two
        # disagree. Anchor everything to the top level.
        top = self._run("rev-parse", "--show-toplevel").strip()
        if top:
            self.subdir = os.path.relpath(
                os.path.abspath(path), top
            ).replace(os.sep, "/")
            if self.subdir == ".":
                self.subdir = ""
            self.path = top
        else:
            self.subdir = ""

    # ------------------------------------------------------------------ util

    def _spawn(self, *args: str) -> subprocess.CompletedProcess:
        """Run git under a timeout and hand back the completed process.

        Every git call goes through here, so none can hang and none can
        escape as a raw traceback. Callers that need to tell a failed
        command apart from one that printed nothing use this directly;
        everything else uses _run.
        """
        cmd = ["git", "-C", self.path, *args]
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise GitError("git executable not found on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise GitError(f"git command timed out: {' '.join(args[:3])}") from exc
        except (OSError, ValueError) as exc:
            # Report text becomes argv, so it can carry a NUL byte
            # (ValueError) or overrun the kernel's argv limit (E2BIG).
            # Neither is a verdict about the reporter: as a GitError it
            # grades UNCHECKABLE instead of killing the run.
            raise GitError(
                f"git {' '.join(args[:3])} could not be run: {exc}"
            ) from exc

    def _run(self, *args: str, check: bool = True) -> str:
        proc = self._spawn(*args)
        if check and proc.returncode != 0:
            raise GitError(
                f"git {' '.join(args[:3])} failed: {proc.stderr.strip()[:200]}"
            )
        return proc.stdout

    # ------------------------------------------------------- revision lookup

    def resolve_rev(self, rev: str) -> Optional[str]:
        """Resolve *rev* to a commit SHA, trying version-tag spellings too.

        Accepts a SHA, branch, tag, or a bare version like ``8.9.0`` which
        is matched against the repository's tags (``v8.9.0``,
        ``curl-8_9_0``, ``release-8.9.0``, ...).
        """
        rev = rev.strip()
        if rev in self._rev_cache:
            return self._rev_cache[rev]
        resolved = None
        for candidate in self._rev_candidates(rev):
            proc = self._spawn(
                "rev-parse", "--verify", "--quiet", candidate + "^{commit}"
            )
            if proc.returncode == 0 and proc.stdout.strip():
                resolved = proc.stdout.strip()
                break
        # Memoized: a report may name the same version many times, and
        # each miss costs two or three processes for an answer that
        # cannot change within a run.
        self._rev_cache[rev] = resolved
        return resolved

    def _rev_candidates(self, rev: str) -> List[str]:
        candidates = [rev]
        if re.fullmatch(r"\d+(?:\.\d+)+[a-z]?", rev):
            candidates.append("v" + rev)
            tag = self.find_tag_for_version(rev)
            if tag:
                candidates.append(tag)
        return candidates

    def rev_name(self, sha: str) -> str:
        """Best human-readable name for a commit (tag or short sha)."""
        out = self._run("describe", "--tags", "--exact-match", sha, check=False)
        name = out.strip()
        return name if name else sha[:12]

    # ---------------------------------------------------------------- files

    def tree_files(self, rev: str) -> List[str]:
        if rev not in self._tree_cache:
            out = self._run("ls-tree", "-r", "--name-only", "-z", rev)
            self._tree_cache[rev] = [p for p in out.split("\0") if p]
        return self._tree_cache[rev]

    def submodule_paths(self, rev: str) -> List[str]:
        """Paths recorded as gitlinks (submodules) at *rev*.

        Their contents are not in this repository, so a claim about a file
        inside one is unverifiable here rather than false.
        """
        if rev in self._submodule_cache:
            return self._submodule_cache[rev]
        out = self._run("ls-tree", "-r", "-z", rev, check=False)
        paths = []
        for entry in out.split("\0"):
            if not entry:
                continue
            meta, _, path = entry.partition("\t")
            fields = meta.split()
            if len(fields) >= 2 and fields[1] == "commit":
                paths.append(path)
        self._submodule_cache[rev] = paths
        return paths

    def file_exists(self, rev: str, path: str) -> bool:
        return path in set(self.tree_files(rev))

    def read_file(self, rev: str, path: str) -> Optional[str]:
        key = (rev, path)
        if key in self._blob_cache:
            return self._blob_cache[key]
        proc = self._spawn("show", f"{rev}:{path}")
        content = proc.stdout if proc.returncode == 0 else None
        self._cache_blob(key, content)
        return content

    def _cache_blob(self, key: Tuple[str, str], content: Optional[str]) -> None:
        """Remember a blob, evicting oldest-first to stay inside both bounds."""
        if content is not None and len(content) > MAX_BLOB_CACHE_CHARS:
            return  # one outsized file is cheaper to re-read than to hold
        self._blob_cache[key] = content
        self._blob_chars += len(content or "")
        while (
            len(self._blob_cache) > MAX_BLOB_CACHE
            or self._blob_chars > MAX_BLOB_CACHE_CHARS
        ):
            # dicts keep insertion order, so this is the oldest entry
            oldest = next(iter(self._blob_cache))
            self._blob_chars -= len(self._blob_cache.pop(oldest) or "")

    @staticmethod
    def _split_lines(content: str) -> List[str]:
        """Split the way a compiler and an editor number lines: on \\n only.

        ``str.splitlines`` also breaks on \\v, \\f and U+2028, which would
        make the line count disagree with the line the reporter is
        looking at.
        """
        lines = content.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        return lines

    def line_count(self, rev: str, path: str) -> Optional[int]:
        content = self.read_file(rev, path)
        if content is None:
            return None
        return len(self._split_lines(content))

    def line_at(self, rev: str, path: str, line: int) -> Optional[str]:
        content = self.read_file(rev, path)
        if content is None:
            return None
        lines = self._split_lines(content)
        if 1 <= line <= len(lines):
            return lines[line - 1].rstrip("\r")
        return None

    # ------------------------------------------------------- working tree

    def is_dirty(self) -> bool:
        """Does the checkout carry changes that are not committed?

        Everything else here reads a pinned revision, which is the whole
        point - but a maintainer running vulnvet on their own checkout
        often has uncommitted work, and a report describing it would be
        graded against a tree that does not contain it yet.
        """
        if self._dirty is None:
            out = self._run("status", "--porcelain", check=False)
            self._dirty = bool(out.strip())
        return self._dirty

    def worktree_has_path(self, path: str) -> bool:
        """Is this path something a future revision of this repo could hold?

        Presence on disk is not enough. Build output, ``.venv`` and
        ``node_modules`` are on disk and are never going to be in any
        revision, so treating them as uncommitted work pointed the
        maintainer at a commit that can never contain the file - and let
        a report cite a plausible build-artifact path to be graded
        softly on any built checkout. git decides instead: tracked, or
        untracked and not ignored.

        The containment check resolves symlinks before comparing.
        ``normpath`` is textual and ``isfile`` follows links, so a
        committed symlink to a vendored tree outside the repository was
        a tunnel straight through the guard.
        """
        if not path:
            return False
        normalized = path.replace(os.sep, "/").strip("/")
        if normalized == ".git" or normalized.startswith(".git/"):
            return False
        root = os.path.realpath(self.path)
        candidate = os.path.realpath(os.path.join(root, path))
        if candidate != root and not candidate.startswith(root + os.sep):
            return False
        if not os.path.isfile(candidate):
            return False
        return normalized in self.worktree_files()

    def worktree_files(self) -> set:
        """Every path git currently considers part of the project.

        Tracked files plus untracked ones that are not ignored: exactly
        the set that a future commit could contain.
        """
        if self._worktree_files is None:
            out = self._run(
                "ls-files", "--cached", "--others", "--exclude-standard",
                "-z", check=False,
            )
            self._worktree_files = {p for p in out.split("\0") if p}
        return self._worktree_files

    def is_shallow(self) -> bool:
        """A shallow clone genuinely is missing history and tags."""
        if self._shallow is None:
            out = self._run(
                "rev-parse", "--is-shallow-repository", check=False
            )
            self._shallow = out.strip() == "true"
        return self._shallow

    def grep_worktree(
        self, word: str, excludes: Optional[List[str]] = None,
    ) -> List[Tuple[str, int, str]]:
        """Whole-word search of the working tree rather than a revision.

        Takes the same exclusions as :meth:`grep_word` and for the same
        reason: a report stored inside the repository must never be
        allowed to corroborate itself, and the working tree is exactly
        where an uncommitted report file lives.
        """
        word = _prepare_needle(word)
        args = ["grep", "-n", "-w", "-I", "-z", "--fixed-strings", "-e", word]
        pathspecs = self._pathspecs(None, excludes)
        if pathspecs:
            args += ["--", *pathspecs]
        out = self._run(*args, check=False)
        return self._parse_grep(out, None)

    def grep_worktree_line(
        self, needle: str, excludes: Optional[List[str]] = None,
    ) -> List[Tuple[str, int, str]]:
        """Exact fixed-string search of the working tree."""
        needle = _prepare_needle(needle)
        args = ["grep", "-n", "-I", "-z", "--fixed-strings", "-e", needle]
        pathspecs = self._pathspecs(None, excludes)
        if pathspecs:
            args += ["--", *pathspecs]
        out = self._run(*args, check=False)
        return self._parse_grep(out, None)

    def head_sha(self) -> Optional[str]:
        """The revision the working tree actually holds, if any.

        A checkout is only evidence about the revision it is on. Without
        this, a tree sitting several releases ahead of the pinned --rev
        looked like uncommitted work in progress.
        """
        if self._head is None:
            try:
                self._head = self._run("rev-parse", "HEAD").strip()
            except GitError:
                self._head = ""
        return self._head or None

    # ----------------------------------------------------------------- grep

    def grep_word(
        self, rev: str, word: str, path: Optional[str] = None,
        ignore_case: bool = False, excludes: Optional[List[str]] = None,
    ) -> List[Tuple[str, int, str]]:
        """Whole-word occurrences of *word* at *rev*: (path, line, text)."""
        word = _prepare_needle(word)
        args = ["grep", "-n", "-w", "-I", "-z"]
        if ignore_case:
            args.append("-i")
        args += ["--fixed-strings", "-e", word, rev]
        pathspecs = self._pathspecs(path, excludes)
        if pathspecs:
            args += ["--", *pathspecs]
        out = self._run(*args, check=False)
        return self._parse_grep(out, rev)

    def grep_fixed_line(
        self, rev: str, needle: str, excludes: Optional[List[str]] = None,
    ) -> List[Tuple[str, int, str]]:
        """Exact fixed-string occurrences of *needle* anywhere at *rev*."""
        needle = _prepare_needle(needle)
        args = ["grep", "-n", "-I", "-z", "--fixed-strings", "-e", needle, rev]
        pathspecs = self._pathspecs(None, excludes)
        if pathspecs:
            args += ["--", *pathspecs]
        out = self._run(*args, check=False)
        return self._parse_grep(out, rev)

    @staticmethod
    def _pathspecs(
        path: Optional[str], excludes: Optional[List[str]]
    ) -> List[str]:
        specs: List[str] = []
        if path:
            specs.append(path)
        for exc in excludes or []:
            specs.append(f":(exclude){exc}")
        return specs

    @staticmethod
    def _parse_grep(out: str, rev: Optional[str]) -> List[Tuple[str, int, str]]:
        """Parse ``git grep -z`` output: rev:path NUL line NUL? text.

        With -z the path is NUL-terminated, so a path containing a colon
        cannot be mistaken for a path:line boundary.
        """
        hits: List[Tuple[str, int, str]] = []
        # A revision search prefixes every record with "<rev>:"; a
        # working-tree search has no prefix at all.
        prefix = rev + ":" if rev else ""
        for record in out.split("\n"):
            if prefix and not record.startswith(prefix):
                continue
            rest = record[len(prefix):]
            path, sep, remainder = rest.partition("\0")
            if not sep:
                continue
            number, sep2, text = remainder.partition("\0")
            if not sep2:
                number, sep2, text = remainder.partition(":")
                if not sep2:
                    continue
            if not number.isdigit():
                continue
            hits.append((path, int(number), text))
            if len(hits) >= MAX_GREP_HITS:
                break
        return hits

    # ----------------------------------------------------------------- tags

    def tags(self) -> List[str]:
        if self._tags is None:
            out = self._run("tag", "--list", check=False)
            self._tags = [t.strip() for t in out.splitlines() if t.strip()]
        return self._tags

    def version_tag_map(self) -> Dict[str, str]:
        """Map of normalized version ("8.9.0") -> actual tag name."""
        mapping: Dict[str, str] = {}
        for tag in self.tags():
            norm = _normalize_version_text(tag)
            if norm and norm not in mapping:
                mapping[norm] = tag
        return mapping

    def find_tag_for_version(self, version: str) -> Optional[str]:
        norm = _normalize_version_text(version) or version
        return self.version_tag_map().get(norm)

    # -------------------------------------------------------------- commits

    def commit_exists(self, ref: str) -> Optional[str]:
        """Return the subject line if *ref* resolves to a commit."""
        proc = self._spawn("log", "-1", "--format=%H %s", ref, "--")
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        return proc.stdout.strip()
