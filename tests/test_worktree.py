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
