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

import re
import subprocess
from typing import Dict, List, Optional, Tuple


class GitError(RuntimeError):
    pass


class NotARepository(GitError):
    pass


#: Cap on grep hits we bother collecting for any single query.
MAX_GREP_HITS = 50


def _normalize_version_text(text: str) -> str:
    """Reduce a tag or version string to a comparable dotted core.

    ``curl-8_9_0`` -> ``8.9.0``; ``v1.2.3`` -> ``1.2.3``; ``rel/2.1`` ->
    ``2.1``. Returns "" when there is nothing version-like inside.
    """
    match = re.search(r"(\d+(?:[._-]\d+)+[a-z]?)$", text.strip())
    if not match:
        return ""
    return match.group(1).replace("_", ".").replace("-", ".")


class Repo:
    def __init__(self, path: str):
        self.path = path
        self._tree_cache: Dict[str, List[str]] = {}
        self._tags: Optional[List[str]] = None
        try:
            out = self._run("rev-parse", "--is-inside-work-tree")
        except GitError as exc:
            raise NotARepository(
                f"{path} is not a git repository (or git is not installed): {exc}"
            ) from exc
        if out.strip() != "true":
            raise NotARepository(f"{path} is not inside a git work tree")

    # ------------------------------------------------------------------ util

    def _run(self, *args: str, check: bool = True) -> str:
        cmd = ["git", "-C", self.path, *args]
        try:
            proc = subprocess.run(
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
        for candidate in self._rev_candidates(rev):
            proc = subprocess.run(
                ["git", "-C", self.path, "rev-parse", "--verify", "--quiet",
                 candidate + "^{commit}"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        return None

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

    def file_exists(self, rev: str, path: str) -> bool:
        return path in set(self.tree_files(rev))

    def read_file(self, rev: str, path: str) -> Optional[str]:
        proc = subprocess.run(
            ["git", "-C", self.path, "show", f"{rev}:{path}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0:
            return None
        return proc.stdout

    def line_count(self, rev: str, path: str) -> Optional[int]:
        content = self.read_file(rev, path)
        if content is None:
            return None
        if content == "":
            return 0
        return content.count("\n") + (0 if content.endswith("\n") else 1)

    def line_at(self, rev: str, path: str, line: int) -> Optional[str]:
        content = self.read_file(rev, path)
        if content is None:
            return None
        lines = content.splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1]
        return None

    # ----------------------------------------------------------------- grep

    def grep_word(
        self, rev: str, word: str, path: Optional[str] = None,
        ignore_case: bool = False, excludes: Optional[List[str]] = None,
    ) -> List[Tuple[str, int, str]]:
        """Whole-word occurrences of *word* at *rev*: (path, line, text)."""
        args = ["grep", "-n", "-w", "-I"]
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
        args = ["grep", "-n", "-I", "--fixed-strings", "-e", needle, rev]
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
    def _parse_grep(out: str, rev: str) -> List[Tuple[str, int, str]]:
        hits: List[Tuple[str, int, str]] = []
        prefix = rev + ":"
        for raw in out.splitlines():
            if not raw.startswith(prefix):
                continue
            rest = raw[len(prefix):]
            # path:line:text - path may not contain ":" in sane repos; be
            # defensive and split from the left on the first two colons
            # that bracket a number.
            m = re.match(r"(.*?):(\d+):(.*)$", rest)
            if not m:
                continue
            hits.append((m.group(1), int(m.group(2)), m.group(3)))
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
        proc = subprocess.run(
            ["git", "-C", self.path, "log", "-1", "--format=%H %s",
             ref, "--"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        return proc.stdout.strip()
