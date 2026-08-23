"""Regression tests for dot-prefixed paths, ``..`` paths and hex spans.

``str.lstrip("./")`` strips a character *set*, not a prefix, so
``.github/workflows/ci.yml`` - the file a CI-injection report exists to
cite - reached the verifier as ``github/workflows/ci.yml`` and came back
NOT FOUND, while ``../src/http.c`` was quietly rebased onto the
repository root and came back VERIFIED. One is the false accusation
test_false_accusation.py is about; the other is the evasion
test_evasion.py::test_fabricated_path_prefix_does_not_verify is about.

The same reflex graded a backticked ``41414141`` as a commit hash, which
tells a reporter writing an honest overflow report that their fill
pattern names no commit. The fence pattern is pinned here too: its
trailing ``[^`]*$`` backtracked quadratically on a long line, which
SECURITY.md promises cannot happen.
"""

import time

import pytest

from conftest import HTTP_C, git
from vulnvet.claims import ClaimType, Verdict
from vulnvet.extract import extract_claims
from vulnvet.gitrepo import Repo
from vulnvet.verify import build_dossier


def vet(text, repo_path, rev="v1.0.0"):
    claims, notes = extract_claims(text)
    return build_dossier("<test>", Repo(repo_path), rev, claims, notes)


def values(claims, ctype):
    return {c.value for c in claims if c.type is ctype}


def verdicts(dossier, ctype):
    return {
        f.claim.value: f.verdict
        for f in dossier.findings
        if f.claim.type is ctype
    }


@pytest.fixture(scope="session")
def ci_repo(tmp_path_factory):
    """The demo project plus the dot-prefixed CI config it ships with."""
    path = tmp_path_factory.mktemp("ci-repo")
    git(path, "init", "-q")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "user.name", "Test")
    git(path, "config", "commit.gpgsign", "false")
    git(path, "config", "tag.gpgsign", "false")

    (path / "src").mkdir()
    (path / "src" / "http.c").write_text(HTTP_C, encoding="utf-8")
    (path / ".github" / "workflows").mkdir(parents=True)
    (path / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: [pull_request_target]\njobs:\n"
        "  build:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    (path / ".gitlab-ci.yml").write_text(
        "build:\n  script: make\n", encoding="utf-8"
    )
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "initial import")
    git(path, "tag", "v1.0.0")
    return str(path)


CI_REPORT = """\
# Workflow injection in the release pipeline

`.github/workflows/ci.yml` runs on `pull_request_target` and checks out
the pull request head, and .gitlab-ci.yml reuses the same runner token.
"""


def test_dot_prefixed_paths_reach_the_verifier_intact():
    claims, _ = extract_claims(CI_REPORT)
    assert values(claims, ClaimType.FILE) == {
        ".github/workflows/ci.yml",
        ".gitlab-ci.yml",
    }


def test_correctly_cited_ci_files_verify(ci_repo):
    """Both files are real and cited exactly right. Grading either of
    them NOT FOUND is the worst thing this tool can do."""
    dossier = vet(CI_REPORT, ci_repo)
    files = verdicts(dossier, ClaimType.FILE)
    assert files[".github/workflows/ci.yml"] is Verdict.VERIFIED
    assert files[".gitlab-ci.yml"] is Verdict.VERIFIED
    assert dossier.count(Verdict.NOT_FOUND) == 0
    assert dossier.strong_signals == []


def test_leading_dot_slash_is_still_stripped(ci_repo):
    """``./src/http.c`` names ``src/http.c``; that prefix is the one the
    old lstrip was there for, and it still has to go."""
    text = "The overflow is in ./src/http.c and nowhere else."
    claims, _ = extract_claims(text)
    assert values(claims, ClaimType.FILE) == {"src/http.c"}
    assert verdicts(vet(text, ci_repo), ClaimType.FILE) == {
        "src/http.c": Verdict.VERIFIED
    }


TRAVERSAL_REPORT = "The overflow is in ../src/http.c, per the build dir.\n"


def test_parent_traversal_path_is_never_verified(ci_repo):
    """``../src/http.c`` is relative to a directory the report never
    named. Rebasing it onto the root let it corroborate src/http.c, which
    is the fabricated-prefix hole from the other direction; the claim is
    dropped at extraction instead, because NOT FOUND would be an
    accusation about a path we cannot resolve either way."""
    claims, _ = extract_claims(TRAVERSAL_REPORT)
    assert not [
        c for c in claims if c.type in (ClaimType.FILE, ClaimType.FILE_LINE)
    ]

    dossier = vet(TRAVERSAL_REPORT, ci_repo)
    assert dossier.count(Verdict.VERIFIED) == 0
    assert dossier.count(Verdict.NOT_FOUND) == 0


def test_traversal_file_line_is_never_verified(ci_repo):
    dossier = vet("The write happens at ../src/http.c:15.\n", ci_repo)
    assert dossier.count(Verdict.VERIFIED) == 0
    assert dossier.count(Verdict.NOT_FOUND) == 0


def test_traversal_attribution_does_not_place_a_symbol():
    """The symbol survives - it is the *file* the report placed it in
    that no longer resolves to one we can check."""
    text = "The function `parse_header_line()` in `../src/http.c` is bad."
    claims, _ = extract_claims(text)
    symbols = {
        c.value: c.extra.get("in_file")
        for c in claims
        if c.type is ClaimType.SYMBOL
    }
    assert symbols.get("parse_header_line") is None
    assert not values(claims, ClaimType.FILE)


OVERFLOW_REPORT = """\
# Stack overflow in header parsing

I fill the 64-byte buffer with `41414141` until the saved return address
is overwritten, using a declared length of `16777216`. The attached PoC
has md5 `d41d8cd98f00b204e9800998ecf8427e`.
"""


def test_fill_patterns_and_checksums_are_not_commit_hashes(ci_repo):
    """Every one of these is hex of commit-ish length, and none of them
    is a commit citation. "no commit with this hash exists" reads as
    fabrication, so the report has to say it meant a revision."""
    claims, _ = extract_claims(OVERFLOW_REPORT)
    assert not values(claims, ClaimType.COMMIT)

    dossier = vet(OVERFLOW_REPORT, ci_repo)
    assert dossier.count(Verdict.NOT_FOUND) == 0
    assert dossier.strong_signals == []


@pytest.mark.parametrize(
    "phrasing",
    [
        "Introduced by commit `%s`.",
        "The offending commit is `%s`.",
        "Fixed in revision `%s` on main.",
        "See sha `%s` for the regression.",
        "The bad rev, `%s`, is still on main.",
    ],
)
def test_commit_context_still_makes_a_hash_checkable(ci_repo, phrasing):
    """The context requirement must not cost a genuine commit citation."""
    short = Repo(ci_repo).resolve_rev("HEAD")[:12]
    claims, _ = extract_claims(phrasing % short)
    assert values(claims, ClaimType.COMMIT) == {short}


def test_a_verified_commit_is_still_verified(ci_repo):
    short = Repo(ci_repo).resolve_rev("HEAD")[:12]
    dossier = vet("Introduced by commit `%s`." % short, ci_repo)
    assert verdicts(dossier, ClaimType.COMMIT) == {short: Verdict.VERIFIED}


def test_a_full_length_hash_needs_no_context():
    """Forty hex characters is a git object id and nothing else, so the
    prose pass reads it whether or not the sentence says "commit"."""
    full = "0123456789abcdef0123456789abcdef01234567"
    claims, _ = extract_claims("The tree at `%s` still has the bug." % full)
    assert values(claims, ClaimType.COMMIT) == {full}


@pytest.mark.parametrize(
    "opener, closer",
    [("```", "```"), ("```c", "```"), ("````c", "````"), ("~~~c", "~~~")],
)
def test_fence_forms_still_delimit_a_quoted_block(opener, closer):
    """Matching only the opener and checking the rest in Python must not
    change which lines open and close a block."""
    text = (
        "The vulnerable code in src/http.c looks like this:\n\n"
        "%s\n    if (len > MAX_HEADER)\n        return -1;\n%s\n"
        % (opener, closer)
    )
    claims, _ = extract_claims(text)
    quotes = [c for c in claims if c.type is ClaimType.QUOTED_CODE]
    assert len(quotes) == 1
    assert quotes[0].extra["hint_path"] == "src/http.c"


def test_fence_scan_is_linear_on_a_hostile_line():
    """SECURITY.md: report text cannot hang the tool. This line took
    ~23 seconds while the fence pattern ended in ``[^`]*$``, and the
    MAX_PROSE_LINE guard does not cover the pass that scans for fences."""
    hostile = "```" + "A" * 100_000 + " `"
    start = time.perf_counter()
    extract_claims("# report\n" + hostile + "\n")
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, "fence scan took %.1fs" % elapsed
