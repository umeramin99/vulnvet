"""The documentation makes checkable claims too.

This project's whole premise is that a confident number should be
checkable against the thing it describes. Its own shop window had
advertised a test count that drifted by 55, and action.yml documented a
set of grades that was missing one the tool emits - so a workflow
gating on the documented values fell through on exactly the report the
missing grade exists to flag.
"""

import pathlib
import re

from vulnvet import claims as claims_module
from vulnvet.claims import GRADES

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_every_grade_in_the_source_is_documented():
    emitted = set(re.findall(r'grade="([^"]+)"', (
        ROOT / "src" / "vulnvet" / "claims.py"
    ).read_text(encoding="utf-8")))
    assert emitted == set(GRADES)


def test_action_yml_documents_every_grade():
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    described = action.split("outputs:", 1)[1].split("strong-signals:", 1)[0]
    # The description is wrapped, so compare on collapsed whitespace.
    described = " ".join(described.split())
    for grade in GRADES:
        assert grade in described, f"action.yml omits the {grade} grade"


def test_the_project_page_states_the_real_test_count():
    page = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    stated = re.search(r"(\d+) tests", page)
    assert stated, "the project page no longer states a test count"
    assert int(stated.group(1)) == _collected_tests()


def _collected_tests() -> int:
    """How many tests this suite has, counted the way pytest counts."""
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         str(ROOT / "tests")],
        capture_output=True, text=True, cwd=str(ROOT),
    ).stdout
    match = re.search(r"(\d+) tests? collected", out)
    assert match, f"could not read a count from pytest:\n{out[-500:]}"
    return int(match.group(1))


#: How each claim type is spelled in the two documents that list them.
#: A new ClaimType with no entry here fails the test below, which is the
#: point: the tables are a promise about what the tool grades.
DOC_LABELS = {
    "symbol": "symbols",
    "stack-frame": "stack frames",
    "quoted-code": "quoted code",
    "file-line": "file:line",
    "file": "files",
    "version": "versions",
    "commit": "commits",
    "cve": "cve ids",
}


def test_every_claim_type_appears_in_both_documents():
    """The project page's table had quietly dropped CVE IDs."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    page = (ROOT / "docs" / "index.html").read_text(encoding="utf-8").lower()
    for claim_type in claims_module.ClaimType:
        label = DOC_LABELS[claim_type.value]
        assert label in readme, f"README omits {claim_type.value}"
        assert label in page, f"the project page omits {claim_type.value}"


def test_the_readme_lists_every_action_output():
    """The README named five of the action's six outputs for weeks.

    A consumer gating on an output the README never mentions has no
    reason to look for it, and the list is mechanically checkable.
    """
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    block = action.split("\noutputs:", 1)[1].split("\nruns:", 1)[0]
    declared = re.findall(r"^  ([a-z][a-z-]*):", block, re.MULTILINE)
    assert declared, "could not read the action's outputs"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    sentence = next(
        line for line in readme.splitlines()
        if "action exposes" in line
    )
    for name in declared:
        assert f"`{name}`" in sentence, f"README omits the {name} output"


def test_the_project_page_does_not_describe_the_replaced_worktree_rule():
    """The page kept saying "if your checkout is dirty" after the code
    stopped gating on dirtiness.

    The working-tree check now fires whenever HEAD is a different
    revision from --rev, which is the ordinary case for a maintainer on
    main grading an older tag - and the page described none of it. This
    pins the specific sentence that went stale rather than trying to
    diff prose against code in general.
    """
    verify = (ROOT / "src" / "vulnvet" / "verify.py").read_text(
        encoding="utf-8"
    )
    # Only meaningful while the check really is revision-based.
    assert "_worktree_differs" in verify
    page = (ROOT / "docs" / "index.html").read_text(encoding="utf-8").lower()
    assert "checkout is dirty" not in page
