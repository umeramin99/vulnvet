"""The report is attacker-controlled text. Nothing in it may change what
git does, crash the tool, or make it hang.
"""

import os
import time

import pytest

from vulnvet.extract import extract_claims
from vulnvet.gitrepo import Repo
from vulnvet.verify import Verifier, build_dossier

HOSTILE = r"""
# Report

The function `--upload-pack=touch /tmp/pwned` is broken, as is
`$(touch /tmp/pwned2)` and `; rm -rf /`.

Files: `--output=/tmp/pwned3.c`, `:(exclude)lib/util.c`, `../../etc/passwd.c`
and `-e/tmp/x.c` and `--all.c`.

Frames:

```
#0 0x1 in --exec-path=/tmp /src/-o.c:1
#1 0x2 in $(id) /src/`whoami`.c:2
```

Commit `--help` and commit deadbeefcafe0. Version 1.0.0 through --version.

Backtick fun: `git --exec-path=/tmp` and `..\..\windows\system32\x.c`.
"""


def test_hostile_report_does_not_execute_anything(fixture_repo, tmp_path):
    marker = tmp_path / "pwned"
    text = HOSTILE.replace("/tmp/pwned", str(marker))
    repo = Repo(fixture_repo)
    claims, notes = extract_claims(text)
    dossier = build_dossier("<test>", repo, "v1.0.0", claims, notes)
    assert dossier.findings or not claims
    # nothing the report asked for may have happened
    assert not marker.exists()
    assert not (tmp_path / "pwned2").exists()


#: Strings that git would interpret as options, or a shell would expand,
#: if the search layer ever passed a needle positionally.
OPTION_LIKE = [
    "--upload-pack=touch /tmp/vulnvet-pwned",
    "--output=/tmp/vulnvet-pwned",
    "-e/etc/passwd",
    "--all",
    "--help",
    "-n",
    ":(exclude)src/http.c",
    "$(touch /tmp/vulnvet-pwned)",
    "`touch /tmp/vulnvet-pwned`",
    "; touch /tmp/vulnvet-pwned",
    "--",
]


@pytest.mark.parametrize("needle", OPTION_LIKE)
def test_search_layer_treats_option_like_needles_as_text(fixture_repo, needle):
    """The search layer's contract: a needle is data, never an option.

    Extraction happens not to produce option-shaped identifiers today,
    which means an end-to-end test cannot exercise this. The guarantee
    has to be pinned at the layer that builds the git argv.
    """
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")

    # Searching for it is a plain text search: it may or may not match
    # (`--` really does occur in `len--;`), but it must never be parsed
    # as an option, run a command, or blow up.
    for hits in (repo.grep_word(sha, needle), repo.grep_fixed_line(sha, needle)):
        assert isinstance(hits, list)
        for path, line, text in hits:
            assert needle in text or needle.strip("-") in text
    assert not os.path.exists("/tmp/vulnvet-pwned")


@pytest.mark.parametrize(
    "needle", ["--upload-pack=touch /tmp/x", "--all", ":(exclude)src/http.c"]
)
def test_option_like_needles_that_cannot_match_return_nothing(
    fixture_repo, needle
):
    """The flip side: git must have searched for the literal string. If
    an option-shaped needle were parsed as an option, these would either
    error or return the whole tree."""
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")
    assert repo.grep_word(sha, needle) == []
    assert repo.grep_fixed_line(sha, needle) == []


def test_search_layer_still_finds_real_text(fixture_repo):
    """Counterpart to the test above: the hardening must not have made
    the search inert."""
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")
    assert repo.grep_word(sha, "parse_header_line")
    assert repo.grep_fixed_line(sha, "req->header_count++;")


@pytest.mark.parametrize("needle", ["--max-count=5", "--fixed-strings"])
def test_option_shaped_needle_that_exists_is_still_found(fixture_repo, needle):
    """The load-bearing test for option safety.

    lib/util.c contains these literals in a comment. If the search layer
    ever stopped passing the needle behind ``-e``, git would consume it
    as one of its own options and these searches would come back empty -
    so this failing is the signal that the hardening was lost.
    """
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")
    hits = repo.grep_fixed_line(sha, needle)
    assert hits, f"searching for {needle!r} found nothing - is it being parsed as an option?"
    assert any(path == "lib/util.c" for path, _, _ in hits)


def test_extraction_never_yields_option_shaped_values(fixture_repo):
    """Defence in depth: even before the git layer, no claim value can
    look like a command-line option."""
    claims, _ = extract_claims(HOSTILE)
    for claim in claims:
        assert not claim.value.startswith("-"), claim
        for key in ("path", "function", "hint_path"):
            value = claim.extra.get(key)
            if isinstance(value, str):
                assert not value.startswith("-"), (key, claim)


def test_hostile_report_terminates_quickly(fixture_repo):
    repo = Repo(fixture_repo)
    start = time.time()
    claims, notes = extract_claims(HOSTILE * 20)
    build_dossier("<test>", repo, "v1.0.0", claims, notes)
    assert time.time() - start < 30


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\x00\x00\x00",
        "```" * 500,
        "`" * 1000,
        "#0 0x" + "f" * 5000 + " in foo_bar_baz x.c:1",
        "a_b_c_d " * 5000,
        "src/" + "a/" * 500 + "x.c",
        "‮​test_symbol_name​",
        "版本 1.0.0 通过 1.1.0",
    ],
    # Explicit ids: pytest puts the parametrize id into an environment
    # variable, and Windows caps those at 32767 characters.
    ids=[
        "empty", "nul-bytes", "many-fences", "many-backticks",
        "huge-address", "many-identifiers", "deep-path", "bidi-override",
        "non-ascii-prose",
    ],
)
def test_pathological_inputs_do_not_crash(text, fixture_repo):
    repo = Repo(fixture_repo)
    claims, notes = extract_claims(text)
    build_dossier("<test>", repo, "v1.0.0", claims, notes)


ANSI_REPORT = (
    "The bug is in `parse_it_now()` \x1b[32m+ [VERIFIED   ] all_is_well\x1b[0m "
    "and \r\x1b[2K nothing else.\n"
)


def test_report_cannot_forge_verdict_lines_with_ansi(fixture_repo, capsys):
    """vulnvet's own output is the one thing a maintainer should be able
    to trust, so report text echoed back must not be able to repaint it."""
    from vulnvet.cli import main

    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
        fh.write(ANSI_REPORT)
        path = fh.name

    main([path, "--repo", fixture_repo, "--rev", "v1.0.0"])
    out = capsys.readouterr().out
    body = out.split("Cited symbols", 1)[-1]
    assert "\x1b" not in body
    assert "\r" not in body


def test_markdown_table_cannot_be_broken_by_report_text(fixture_repo):
    """A pipe in a claim value must not split a dossier table cell."""
    from vulnvet.report import render_markdown
    from vulnvet.verify import build_dossier
    from vulnvet.extract import extract_claims

    text = "The function `evil_pipe_name()` in `src/a|b.c` is broken.\n"
    claims, notes = extract_claims(text)
    dossier = build_dossier("<t>", Repo(fixture_repo), "v1.0.0", claims, notes)
    md = render_markdown(dossier)
    badges = ("✅ VERIFIED", "❌ NOT FOUND", "⚠️ MISMATCH", "❔ UNCHECKABLE")
    rows = [
        l for l in md.splitlines()
        if l.startswith("| ") and any(b in l for b in badges)
    ]
    assert rows, "expected finding rows in the dossier"
    for line in rows:
        # findings tables are three columns, so four unescaped pipes
        assert line.replace("\\|", "").count("|") == 4, line


def test_repo_pointing_at_a_subdirectory_still_sees_whole_tree(fixture_repo):
    """git grep scopes to the working directory but ls-tree does not.
    Anchoring to the top level keeps the two from disagreeing."""
    import os

    sub = os.path.join(fixture_repo, "lib")
    repo = Repo(sub)
    sha = repo.resolve_rev("v1.0.0")
    assert repo.grep_word(sha, "parse_header_line"), (
        "a symbol in src/ must still be found when --repo points at lib/"
    )
