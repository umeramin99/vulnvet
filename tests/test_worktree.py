"""The revision is what gets graded; the working tree can only excuse.

A maintainer usually runs this on a checkout with uncommitted work, and a
report describing that work is not a fabricated report. vulnvet looks
outside the pinned revision in exactly one direction - to withdraw a
negative verdict, never to grant a positive one.
"""

from vulnvet.claims import ClaimType, Verdict
from vulnvet.extract import extract_claims
from vulnvet.gitrepo import Repo
from vulnvet.verify import build_dossier


def vet(text, repo_path, rev=None):
    claims, notes = extract_claims(text)
    return build_dossier("<test>", Repo(repo_path), rev, claims, notes)


def verdicts(dossier, ctype):
    return {
        f.claim.value: f.verdict
        for f in dossier.findings
        if f.claim.type is ctype
    }


UNCOMMITTED_REPORT = (
    "The bug is in `validate_length()` in `src/http.c`, and the helper "
    "in src/newfile.c is also affected.\n"
)


def test_uncommitted_work_is_not_a_fabrication(dirty_repo):
    """This was the whole bug: a maintainer with work in progress got
    SEVERE GROUNDING FAILURES on a report that described their tree
    correctly."""
    dossier = vet(UNCOMMITTED_REPORT, dirty_repo)

    assert verdicts(dossier, ClaimType.SYMBOL)["validate_length"] is (
        Verdict.MISMATCH
    )
    assert verdicts(dossier, ClaimType.FILE)["src/newfile.c"] is Verdict.MISMATCH
    assert dossier.strong_signals == []
    assert dossier.count(Verdict.NOT_FOUND) == 0
    assert dossier.assessment().grade != "SEVERE GROUNDING FAILURES"


def test_the_dossier_says_the_checkout_is_dirty(dirty_repo):
    dossier = vet(UNCOMMITTED_REPORT, dirty_repo)
    assert any("uncommitted" in note for note in dossier.notes)


def test_the_evidence_explains_rather_than_accuses(dirty_repo):
    dossier = vet(UNCOMMITTED_REPORT, dirty_repo)
    for finding in dossier.findings:
        if finding.verdict is Verdict.MISMATCH:
            assert "working tree" in finding.evidence
            assert "--rev" in finding.evidence


def test_the_working_tree_can_never_manufacture_a_verified(dirty_repo):
    """Exculpatory only. A symbol that exists nowhere at all must still
    come back NOT FOUND, and nothing uncommitted may grade VERIFIED."""
    dossier = vet(
        "The flaw is in `totally_invented_symbol()` and in "
        "`validate_length()`.\n",
        dirty_repo,
    )
    symbols = verdicts(dossier, ClaimType.SYMBOL)
    assert symbols["totally_invented_symbol"] is Verdict.NOT_FOUND
    assert symbols["validate_length"] is Verdict.MISMATCH
    assert len(dossier.strong_signals) == 1


def test_a_clean_checkout_is_graded_exactly_as_before(fixture_repo):
    """The exculpatory check must not fire on a clean tree - that is the
    path every other test and both shipped examples exercise."""
    dossier = vet(
        "The flaw is in `totally_invented_symbol()`.\n",
        fixture_repo,
        rev="v1.0.0",
    )
    symbols = verdicts(dossier, ClaimType.SYMBOL)
    assert symbols["totally_invented_symbol"] is Verdict.NOT_FOUND
    assert not any("uncommitted" in note for note in dossier.notes)


# --- suggesting the revision the report itself names ---------------------

def test_the_note_names_a_version_the_report_gave(fixture_repo):
    """Telling someone to "re-run with --rev <version>" when the report is
    sitting right there naming one is a step the tool can take itself."""
    dossier = vet("The flaw affects version 1.0.0 of the parser.\n", fixture_repo)
    notes = " ".join(dossier.notes)
    assert "--rev 1.0.0" in notes


def test_no_version_in_the_report_keeps_the_general_advice(fixture_repo):
    dossier = vet("The parser is broken somehow.\n", fixture_repo)
    notes = " ".join(dossier.notes)
    assert "--rev <version>" in notes


def test_a_version_this_repository_lacks_is_never_suggested(fixture_repo):
    """Sending someone after a revision that does not exist would turn one
    confusing run into two."""
    dossier = vet("The flaw affects version 99.1.0.\n", fixture_repo)
    notes = " ".join(dossier.notes)
    assert "--rev 99.1.0" not in notes
    assert "--rev <version>" in notes


def test_a_third_partys_version_is_never_suggested(fixture_repo):
    """"Tested on Ubuntu 22.04" is not a revision of this project."""
    dossier = vet("Tested on Ubuntu 22.04 against the parser.\n", fixture_repo)
    assert "--rev 22.04" not in " ".join(dossier.notes)


# --- the report file is never evidence for itself ------------------------

def test_an_uncommitted_report_cannot_corroborate_its_own_invention(dirty_repo):
    """Self-exclusion has to reach the working tree too.

    The revision search already refused to read the report file. The
    working-tree search did not, so dropping the report into the repo -
    the obvious thing to do - let every fabricated symbol in it find
    itself on disk and grade MISMATCH instead of NOT FOUND.
    """
    import os

    report = os.path.join(dirty_repo, "report.md")
    text = "The flaw is in `totally_invented_symbol()`.\n"
    with open(report, "w", encoding="utf-8") as fh:
        fh.write(text)

    claims, notes = extract_claims(text)
    dossier = build_dossier(report, Repo(dirty_repo), None, claims, notes)
    assert verdicts(dossier, ClaimType.SYMBOL)["totally_invented_symbol"] is (
        Verdict.NOT_FOUND
    )
    assert len(dossier.strong_signals) == 1


# --- a checkout newer than the graded revision ---------------------------

def test_a_clean_checkout_ahead_of_the_revision_still_excuses(ahead_repo):
    """Nothing is uncommitted here - HEAD is simply newer than --rev.

    This is the ordinary case: the maintainer is on main, the report is
    about a release. A check gated on dirtiness alone never looked, and
    code that plainly exists one tag later was called invented.
    """
    dossier = vet(
        "The flaw is in `validate_body_length()`.\n", ahead_repo, rev="v1.0.0"
    )
    finding = next(
        f for f in dossier.findings if f.claim.type is ClaimType.SYMBOL
    )
    assert finding.verdict is Verdict.MISMATCH
    assert "not v1.0.0" in finding.evidence
    assert dossier.strong_signals == []


def test_being_ahead_does_not_excuse_something_absent_everywhere(ahead_repo):
    dossier = vet(
        "The flaw is in `totally_invented_symbol()`.\n", ahead_repo, rev="v1.0.0"
    )
    finding = next(
        f for f in dossier.findings if f.claim.type is ClaimType.SYMBOL
    )
    assert finding.verdict is Verdict.NOT_FOUND
    assert finding.is_strong_signal


# --- the suggested revision must be one that can contain the bug ---------

def test_prior_to_a_release_suggests_the_release_before_it(fixture_repo):
    """"Affects everything prior to 1.1.0" names the fix, not a victim.

    Suggesting 1.1.0 sent the maintainer to grade a truthful report
    against the one release that cannot contain the bug.
    """
    dossier = vet(
        "Affects all versions prior to 1.1.0.\n", fixture_repo
    )
    notes = " ".join(dossier.notes)
    assert "--rev 1.0.0" in notes
    assert "--rev 1.1.0" not in notes


def test_fixed_in_a_release_suggests_the_release_before_it(fixture_repo):
    dossier = vet("This was fixed in 1.1.0.\n", fixture_repo)
    notes = " ".join(dossier.notes)
    assert "--rev 1.0.0" in notes
    assert "--rev 1.1.0" not in notes


def test_a_fix_boundary_with_nothing_below_it_suggests_nothing(fixture_repo):
    dossier = vet("This was fixed in 0.1.0.\n", fixture_repo)
    notes = " ".join(dossier.notes)
    assert "--rev <version>" in notes


# --- the other claim types the dossier promises to cover -----------------

def test_a_backtrace_into_uncommitted_work_is_not_a_fabrication(dirty_repo):
    """A crash trace is how a real reporter names a function.

    The dossier's own note promises that anything only in the working
    tree is reported as such - and stack frames, which feed the strong
    signal count, were the one claim type that never got the check.
    """
    text = (
        "Crash:\n\n```\n"
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x7f00 in validate_length /build/dirty/src/http.c:6\n"
        "```\n"
    )
    dossier = vet(text, dirty_repo)
    frame = next(
        f for f in dossier.findings if f.claim.type is ClaimType.STACK_FRAME
    )
    assert frame.verdict is Verdict.MISMATCH
    assert "working tree" in frame.evidence
    assert dossier.strong_signals == []


def test_a_fabricated_backtrace_is_still_a_fabrication(dirty_repo):
    text = (
        "Crash:\n\n```\n"
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x7f00 in totally_invented_symbol /build/dirty/src/http.c:6\n"
        "```\n"
    )
    dossier = vet(text, dirty_repo)
    frame = next(
        f for f in dossier.findings if f.claim.type is ClaimType.STACK_FRAME
    )
    assert frame.verdict is Verdict.NOT_FOUND
    assert frame.is_strong_signal


def test_quoted_uncommitted_code_is_not_a_fabrication(dirty_repo):
    text = (
        "The vulnerable code in src/http.c reads:\n\n```c\n"
        "int validate_length(size_t n)\n"
        "{\n"
        "    size_t limit = 1024;\n"
        "    if (n >= limit)\n"
        "        return 0;\n"
        "}\n"
        "```\n"
    )
    dossier = vet(text, dirty_repo)
    quote = next(
        f for f in dossier.findings if f.claim.type is ClaimType.QUOTED_CODE
    )
    assert quote.verdict is Verdict.MISMATCH
    assert "working tree" in quote.evidence


def test_quoted_code_that_is_nowhere_is_still_a_fabrication(dirty_repo):
    text = (
        "The vulnerable code in src/http.c reads:\n\n```c\n"
        "int sanitize_priority_frame(frame_ctx *ctx)\n"
        "{\n"
        "    ctx->weight = frame->weight * 256;\n"
        "    return apply_priority_update(ctx);\n"
        "}\n"
        "```\n"
    )
    dossier = vet(text, dirty_repo)
    quote = next(
        f for f in dossier.findings if f.claim.type is ClaimType.QUOTED_CODE
    )
    assert quote.verdict is Verdict.NOT_FOUND
    assert quote.is_strong_signal


# --- what counts as "present in the working tree" ------------------------

def test_build_output_is_not_evidence_of_uncommitted_work(dirty_repo):
    """An ignored file is on disk and will never be in any revision.

    Accepting it withdrew a NOT FOUND and told the maintainer to re-run
    at a revision that cannot contain the file - and let a report cite a
    plausible build-artifact path to be graded softly on any checkout
    that has been built.
    """
    import os

    with open(os.path.join(dirty_repo, ".gitignore"), "w", encoding="utf-8") as fh:
        fh.write("build/\n")
    os.mkdir(os.path.join(dirty_repo, "build"))
    with open(os.path.join(dirty_repo, "build", "generated.c"), "w",
              encoding="utf-8") as fh:
        fh.write("int generated_entry(void) { return 0; }\n")

    dossier = vet("The flaw is in build/generated.c.\n", dirty_repo)
    assert verdicts(dossier, ClaimType.FILE)["build/generated.c"] is (
        Verdict.NOT_FOUND
    )


def test_a_symlink_out_of_the_repo_is_not_part_of_it(dirty_repo, tmp_path):
    """The containment guard was textual; the existence test followed
    links, so a committed symlink was a tunnel to anywhere."""
    import os

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "vendored.c").write_text("int vendored(void) { return 0; }\n")
    link = os.path.join(dirty_repo, "deps")
    try:
        os.symlink(str(outside), link)
    except (OSError, NotImplementedError):  # Windows without privileges
        import pytest

        pytest.skip("symlinks unavailable")

    dossier = vet("The flaw is in deps/vendored.c.\n", dirty_repo)
    assert verdicts(dossier, ClaimType.FILE)["deps/vendored.c"] is (
        Verdict.NOT_FOUND
    )


def test_a_version_this_report_pins_to_this_project_is_suggested(fixture_repo):
    """"affects <project> 1.0.0" is the most explicit thing a report can
    say. Discarding it for carrying a product word at all fell back to
    the generic advice the suggestion exists to replace."""
    import os

    name = os.path.basename(fixture_repo)
    dossier = vet(f"This affects {name} 1.0.0.\n", fixture_repo)
    assert "--rev 1.0.0" in " ".join(dossier.notes)


def test_a_range_falls_back_to_its_lower_bound(fixture_repo):
    """Collapsing a range to its end alone dropped a real lower bound
    whenever the upper one was not a release this repository has."""
    dossier = vet(
        "The flaw affects versions 1.0.0 through 9.9.9.\n", fixture_repo
    )
    assert "--rev 1.0.0" in " ".join(dossier.notes)


def test_no_re_run_is_suggested_when_head_already_is_that_release(
    fixture_repo,
):
    """HEAD is v1.1.0 here, so advising --rev 1.1.0 asks for a re-run
    that reproduces the identical dossier."""
    dossier = vet("This affects version 1.1.0.\n", fixture_repo)
    notes = " ".join(dossier.notes)
    assert "--rev 1.1.0" not in notes
    assert "--rev <version>" in notes


def test_only_the_files_that_differ_are_searched(dirty_repo):
    """The exculpatory search is narrowed to what actually differs.

    Every other file is byte-identical to the revision, so the revision
    search has already answered for it - and searching the whole tree
    again doubled the cost of every NOT FOUND verdict.
    """
    repo = Repo(dirty_repo)
    paths = repo.paths_differing_from(repo.resolve_rev("HEAD"))
    assert set(paths) == {"src/http.c", "src/newfile.c"}


def test_an_ignored_file_is_not_a_difference(dirty_repo):
    import os

    with open(os.path.join(dirty_repo, ".gitignore"), "w", encoding="utf-8") as fh:
        fh.write("out/\n")
    os.mkdir(os.path.join(dirty_repo, "out"))
    with open(os.path.join(dirty_repo, "out", "built.c"), "w",
              encoding="utf-8") as fh:
        fh.write("int built(void) { return 0; }\n")

    repo = Repo(dirty_repo)
    paths = repo.paths_differing_from(repo.resolve_rev("HEAD"))
    assert not any(p.startswith("out/") for p in paths)
