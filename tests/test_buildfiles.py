"""Build, CI and attachment citations must not read as fabrications.

Two ways an entirely correct report was told its citations do not check
out. A symbol that lives only in a Makefile recipe or a workflow step
was graded "only outside source code ... which is where a removed
function still gets mentioned" - but build-time injection and workflow
script injection are real bug classes, and those files are the subject
of such a report, not prose about it. And a reporter writing "I have
attached poc.py" had their own attachment graded as a repository path
and came back NOT FOUND; naming your own script is not a citation of
the codebase.

The counterpart the fix must not break is pinned in
test_evasion.py::test_a_symbol_only_in_release_notes_is_not_corroborated:
curl's RELEASE-NOTES and docs/libcurl/symbols-in-versions list every
symbol the project ever had, deleted ones included, and must stay
outside the source set.
"""

import pytest

from conftest import HTTP_C, git
from vulnvet.claims import ClaimType, Verdict
from vulnvet.extract import extract_claims
from vulnvet.gitrepo import Repo
from vulnvet.verify import build_dossier


def vet(text, repo_path, rev="v1.0.0"):
    claims, notes = extract_claims(text)
    return build_dossier("<test>", Repo(repo_path), rev, claims, notes)


def verdicts(dossier, ctype):
    return {
        f.claim.value: f.verdict
        for f in dossier.findings
        if f.claim.type is ctype
    }


MAKEFILE = """\
CFLAGS = -O2

all: build_release_tarball

build_release_tarball:
\ttar czf out.tgz src
"""

RELEASE_WORKFLOW = """\
name: release
on: [push]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: ./upload_release_artifacts "${{ github.event.head_commit.message }}"
"""


@pytest.fixture(scope="session")
def build_repo(tmp_path_factory):
    """The demo project plus the build and CI files it ships with."""
    path = tmp_path_factory.mktemp("build-repo")
    git(path, "init", "-q")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "user.name", "Test")
    git(path, "config", "commit.gpgsign", "false")
    git(path, "config", "tag.gpgsign", "false")

    (path / "src").mkdir()
    (path / "src" / "http.c").write_text(HTTP_C, encoding="utf-8")
    (path / "Makefile").write_text(MAKEFILE, encoding="utf-8")
    (path / "CMakeLists.txt").write_text(
        "project(demo)\nadd_custom_target(sign_release_bundle COMMAND echo)\n",
        encoding="utf-8",
    )
    (path / ".github" / "workflows").mkdir(parents=True)
    (path / ".github" / "workflows" / "release.yml").write_text(
        RELEASE_WORKFLOW, encoding="utf-8"
    )
    (path / "RELEASE-NOTES").write_text(
        "This release removed retired_legacy_handler.\n", encoding="utf-8"
    )
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "initial import")
    git(path, "tag", "v1.0.0")
    return str(path)


# ------------------------------------------------------- build and CI files


def test_build_and_ci_files_are_source_not_documentation():
    from vulnvet.verify import _is_doc_path, _is_source_path

    assert _is_source_path("Makefile")
    assert _is_source_path("GNUmakefile")
    assert _is_source_path("CMakeLists.txt")
    assert _is_source_path("configure")
    assert _is_source_path("cmake/FindSSL.cmake")
    assert _is_source_path("build/rules.mk")
    assert _is_source_path("m4/curl-openssl.m4")
    assert _is_source_path("Dockerfile")
    assert _is_source_path("meson.build")
    assert _is_source_path(".github/workflows/release.yml")
    assert not _is_doc_path(".github/workflows/release.yml")


def test_release_notes_are_still_not_source():
    """The extension-less prose curl ships must stay outside the source
    set: this is the case test_evasion.py pins, and widening the source
    set is exactly the change that could regress it."""
    from vulnvet.verify import _is_source_path

    assert not _is_source_path("RELEASE-NOTES")
    assert not _is_source_path("docs/libcurl/symbols-in-versions")
    assert not _is_source_path("docs/KNOWN_BUGS")
    assert not _is_source_path("CHANGELOG.md")


WORKFLOW_INJECTION = """\
# Command injection in the release workflow

The `publish` job interpolates the commit message straight into a shell
command, so `upload_release_artifacts()` runs attacker-controlled text.
The same unquoted expansion reaches `build_release_tarball()` and
`sign_release_bundle()`.
"""


def test_symbols_defined_only_in_build_files_are_corroborated(build_repo):
    """Every name in this report exists at the cited revision. Reporting
    them as mentions "in documentation, release notes or other non-source
    files" tells a correct reporter their citations are stale."""
    dossier = vet(WORKFLOW_INJECTION, build_repo)
    symbols = verdicts(dossier, ClaimType.SYMBOL)

    assert symbols["upload_release_artifacts"] is Verdict.VERIFIED
    assert symbols["build_release_tarball"] is Verdict.VERIFIED
    assert symbols["sign_release_bundle"] is Verdict.VERIFIED
    for finding in dossier.findings:
        assert "documentation" not in finding.evidence, finding

    assert dossier.count(Verdict.NOT_FOUND) == 0
    assert dossier.strong_signals == []
    assert dossier.assessment().grade == "FULLY GROUNDED"


def test_a_symbol_only_in_release_notes_is_still_not_corroborated(build_repo):
    """The counterpart: a name the release notes mention as removed is
    still not code the project ships."""
    dossier = vet(
        "The bug is in `retired_legacy_handler()`, still shipped in 1.0.0.",
        build_repo,
    )
    symbols = verdicts(dossier, ClaimType.SYMBOL)
    assert symbols["retired_legacy_handler"] is Verdict.MISMATCH


def test_a_fabricated_build_symbol_is_still_caught(build_repo):
    """Widening the source set must not blind the tool: a name in no
    file at all is still absent."""
    dossier = vet(
        "The injection happens in `frobnicate_release_manifest()`.",
        build_repo,
    )
    symbols = verdicts(dossier, ClaimType.SYMBOL)
    assert symbols["frobnicate_release_manifest"] is Verdict.NOT_FOUND


# ------------------------------------------------------ attached PoC files


ATTACHED_POC = """\
# Heap overflow in handle_request

I have attached poc.py which reproduces the crash in under a second.
See exploit.py attached for the weaponised version.
"""


def test_attached_poc_filenames_are_not_missing_repository_files(fixture_repo):
    """"I have attached poc.py" cites the reporter's own script. The
    repository was never asked about it, so it cannot answer - and
    NOT FOUND here reads as "you made this file up"."""
    dossier = vet(ATTACHED_POC, fixture_repo)
    files = verdicts(dossier, ClaimType.FILE)

    assert files["poc.py"] is Verdict.UNCHECKABLE
    assert files["exploit.py"] is Verdict.UNCHECKABLE
    for finding in dossier.findings:
        assert "attached file" in finding.evidence, finding

    assert dossier.count(Verdict.NOT_FOUND) == 0
    assert dossier.strong_signals == []


def test_a_poc_name_with_a_directory_is_still_a_path_claim(fixture_repo):
    """The gate is the missing directory. "tests/poc.py" describes a
    location in the tree, and that is a claim vulnvet can check."""
    dossier = vet("The regression test is in tests/poc.py.", fixture_repo)
    files = verdicts(dossier, ClaimType.FILE)
    assert files["tests/poc.py"] is Verdict.NOT_FOUND


def test_a_bare_document_still_reads_as_an_attached_document(fixture_repo):
    """The pre-existing wording for prose attachments is unchanged; the
    PoC case is a second gate, not a rewrite of the first."""
    dossier = vet("Full write-up in report.md.", fixture_repo)
    files = verdicts(dossier, ClaimType.FILE)
    assert files["report.md"] is Verdict.UNCHECKABLE
    assert any(
        "attached document" in f.evidence for f in dossier.findings
    )


def test_a_line_number_does_not_turn_an_attachment_into_a_path(fixture_repo):
    """"poc.py" is UNCHECKABLE but "poc.py:42" was NOT FOUND, so a single
    dossier could excuse and accuse the same file two lines apart. The
    line number says where to look inside the attachment, not that the
    repository should have one."""
    dossier = vet(
        "I have attached poc.py; the crash is at poc.py:42, and "
        "report.md:12 has the write-up.",
        fixture_repo,
    )
    lines = verdicts(dossier, ClaimType.FILE_LINE)

    assert lines["poc.py:42"] is Verdict.UNCHECKABLE
    assert lines["report.md:12"] is Verdict.UNCHECKABLE
    assert dossier.count(Verdict.NOT_FOUND) == 0
    assert dossier.strong_signals == []


# ----------------------------------------------------------- version series


def test_a_version_series_matches_its_release_tags(fixture_repo):
    """"affects version 1.0" is how people name the 1.0 line. The tag is
    v1.0.0, and reporting no match accuses a reporter over a convention."""
    dossier = vet("This affects version 1.0.", fixture_repo)
    versions = verdicts(dossier, ClaimType.VERSION)
    assert versions["1.0"] is Verdict.VERIFIED
    assert dossier.count(Verdict.NOT_FOUND) == 0


def test_a_version_series_range_matches_and_names_real_tags(fixture_repo):
    dossier = vet("The flaw affects versions 1.0 through 1.1.", fixture_repo)
    findings = [
        f for f in dossier.findings if f.claim.type is ClaimType.VERSION
    ]
    assert len(findings) == 1
    assert findings[0].verdict is Verdict.VERIFIED
    assert "v1.0.0 .. v1.1.0" in findings[0].evidence


def test_a_version_that_was_never_released_is_still_not_found(fixture_repo):
    """The series match is a prefix on a component boundary, so it does
    not turn every number into a release."""
    assert verdicts(
        vet("Reproduced on version 9.9.9.", fixture_repo), ClaimType.VERSION
    )["9.9.9"] is Verdict.NOT_FOUND
    assert verdicts(
        vet("Affects version 2.5.", fixture_repo), ClaimType.VERSION
    )["2.5"] is Verdict.NOT_FOUND

    from vulnvet.verify import Verifier

    # "1" has no dotted core, so it names no series - it must not reach
    # the 1.x tags by prefix.
    assert Verifier._series_tags("1", {"1.0.0": "v1.0.0"}) == []
    assert Verifier._series_tags("1.0", {"1.0.0": "v1.0.0"}) == ["v1.0.0"]
    # A component boundary, not a character prefix: 1.1 is not 1.10.
    assert Verifier._series_tags("1.1", {"1.10.2": "v1.10.2"}) == []
