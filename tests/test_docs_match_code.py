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
