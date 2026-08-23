"""Report text becomes git's argv, and argv has hard kernel limits.

README.md and SECURITY.md both promise that report text cannot hang the
tool or exhaust memory. A NUL byte inside a graded code block, and a
quoted line longer than the kernel's per-argument limit, both used to
escape as a raw Python traceback instead - which, under the Action's
`set -euo pipefail`, left a zero-byte dossier behind. Neither is a
verdict about the reporter, so neither may end the run.
"""

import subprocess

import pytest

from vulnvet import gitrepo
from vulnvet.claims import ClaimType, Verdict
from vulnvet.cli import main
from vulnvet.extract import extract_claims
from vulnvet.gitrepo import MAX_NEEDLE_CHARS, GitError, Repo
from vulnvet.verify import build_dossier

#: A lead-in that marks the block as quoted from the tree (so it is
#: graded at all), then three lines that really are in the fixture, one
#: of which the test corrupts.
QUOTED_REPORT = """\
# Report

The vulnerable code in `src/http.c` looks like this:

```c
static int parse_header_line(struct request *req, const char *line, size_t len)
%s
    req->header_count++;
```
"""


def write_report(tmp_path, content):
    report = tmp_path / "report.md"
    report.write_text(content, encoding="utf-8")
    return str(report)


def quoted_code_finding(dossier):
    for finding in dossier.findings:
        if finding.claim.type is ClaimType.QUOTED_CODE:
            return finding
    raise AssertionError("the code block was not graded at all")


# ------------------------------------------------------ argv-hostile text


def test_nul_byte_in_quoted_code_still_produces_a_dossier(
    fixture_repo, tmp_path, capsys
):
    """A NUL cannot be passed to execve, so it used to reach subprocess
    as ValueError and kill the run mid-dossier."""
    path = write_report(tmp_path, QUOTED_REPORT % "    if (len > MAX_HEADER\x00)")
    rc = main([path, "--repo", fixture_repo, "--rev", "v1.0.0", "--no-color"])
    out = capsys.readouterr().out
    assert rc in (0, 1)
    assert "Summary" in out
    assert "Traceback" not in out


def test_a_nul_byte_does_not_stop_a_real_line_from_matching(fixture_repo):
    """Dropping the NUL is the generous direction: git grep -I would
    never match a line containing one, so removing it can only help the
    reporter's line corroborate."""
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")
    hits = repo.grep_fixed_line(sha, "req->head\x00er_count++;")
    assert any(path == "src/http.c" for path, _, _ in hits)


def test_over_long_quoted_line_is_uncheckable_not_a_crash(fixture_repo):
    """A single argv element past the kernel's limit fails the whole
    exec (E2BIG). That is something vulnvet could not check, not
    something the reporter got wrong."""
    text = QUOTED_REPORT % ("    int x = " + "a" * 200000 + ";")
    claims, notes = extract_claims(text)
    dossier = build_dossier("<test>", Repo(fixture_repo), "v1.0.0", claims, notes)
    finding = quoted_code_finding(dossier)
    assert finding.verdict is Verdict.UNCHECKABLE
    assert finding.evidence.strip()
    assert dossier.count(Verdict.NOT_FOUND) == 0


@pytest.mark.parametrize("size", [MAX_NEEDLE_CHARS + 1, 200000])
def test_over_long_needles_raise_git_error(fixture_repo, size):
    """GitError is the one exception the verifier turns into
    UNCHECKABLE; an OSError from subprocess is not."""
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")
    for search in (repo.grep_word, repo.grep_fixed_line):
        with pytest.raises(GitError):
            search(sha, "a" * size)


def test_needle_at_the_limit_is_still_searched(fixture_repo):
    """The cap must not have made the search inert below it."""
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")
    assert repo.grep_fixed_line(sha, "a" * MAX_NEEDLE_CHARS) == []
    assert repo.grep_fixed_line(sha, "req->header_count++;")


# ----------------------------------------------------------- no hangs


def spy_on_git(monkeypatch):
    """Record every git subprocess the module spawns."""
    calls = []
    real_run = subprocess.run

    def spy(cmd, *args, **kwargs):
        calls.append((list(cmd) if isinstance(cmd, list) else cmd, kwargs))
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(gitrepo.subprocess, "run", spy)
    return calls


def test_every_git_call_carries_a_timeout(fixture_repo, monkeypatch):
    """rev-parse, git show and git log were hand-rolled without one, so a
    wedged git hung the tool forever while the rest capped at 120s."""
    repo = Repo(fixture_repo)
    calls = spy_on_git(monkeypatch)
    sha = repo.resolve_rev("v1.0.0")
    repo.read_file(sha, "src/http.c")
    repo.commit_exists(sha)
    repo.grep_word(sha, "parse_header_line")
    repo.tags()
    assert calls
    for cmd, kwargs in calls:
        assert kwargs.get("timeout"), cmd


# ------------------------------------------------------------- blob cache


def test_repeated_reads_of_one_file_spawn_one_git_show(
    fixture_repo, monkeypatch
):
    """read_file, line_count and line_at each re-fetched the whole blob,
    so ten claims against one file cost twenty processes."""
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")
    calls = spy_on_git(monkeypatch)
    for _ in range(10):
        assert repo.line_count(sha, "src/http.c")
        assert repo.line_at(sha, "src/http.c", 4)
    shows = [cmd for cmd, _ in calls if "show" in cmd]
    assert len(shows) == 1, f"{len(shows)} git show processes for one blob"


def test_the_blob_cache_is_keyed_on_the_revision(fixture_repo):
    """src/http.c gained two lines in v1.1.0. A cache keyed on the path
    alone would answer the second question with the first tree's file -
    and a wrong line count is a MISMATCH against an honest reporter."""
    repo = Repo(fixture_repo)
    old = repo.resolve_rev("v1.0.0")
    new = repo.resolve_rev("v1.1.0")
    first = repo.line_count(old, "src/http.c")
    assert repo.line_count(new, "src/http.c") == first + 2
    assert repo.line_count(old, "src/http.c") == first


def test_the_blob_cache_does_not_leak_between_repositories(
    fixture_repo, submodule_repo
):
    other = Repo(submodule_repo)
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")
    assert repo.read_file(sha, "src/http.c")
    # that revision does not exist over here, and no cache may pretend it does
    assert other.read_file(sha, "src/http.c") is None


def test_the_blob_cache_is_bounded(fixture_repo, monkeypatch):
    """A report citing far more files than the cache holds must not pin
    them all in memory."""
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")
    monkeypatch.setattr(gitrepo, "MAX_BLOB_CACHE", 2)
    for name in ("src/http.c", "lib/util.c", "README.md"):
        repo.read_file(sha, name)
    assert len(repo._blob_cache) <= 2
