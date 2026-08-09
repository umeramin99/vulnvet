"""Regression tests for the failure mode that matters most.

Grading an honest report as fabricated is worse than missing a fabricated
one. Each test here is a report a real person could plausibly file, and
the assertion is that vulnvet does not accuse them.
"""

from vulnvet.claims import ClaimType, Verdict
from vulnvet.extract import extract_claims
from vulnvet.gitrepo import Repo
from vulnvet.verify import build_dossier


def vet(text, fixture_repo, rev="v1.0.0"):
    claims, notes = extract_claims(text)
    return build_dossier("<test>", Repo(fixture_repo), rev, claims, notes)


def verdicts(dossier, ctype):
    return {
        f.claim.value: f.verdict
        for f in dossier.findings
        if f.claim.type is ctype
    }


DEPENDENCY_TRACE = """\
# Use-after-free reachable from header parsing

Built with ASAN against 1.0.0:

```
==9==ERROR: AddressSanitizer: heap-use-after-free
    #0 0x55a1 in parse_header_line /home/build/demo/src/http.c:15
    #1 0x55a2 in ossl_statem_client_read_transition /home/build/openssl/ssl/statem/statem_clnt.c:392
    #2 0x55a3 in z_inflate /home/build/zlib/inflate.c:1290
    #3 0x55a4 in nghttp2_session_mem_recv /home/build/nghttp2/lib/nghttp2_session.c:6789
```
"""


def test_dependency_frames_are_not_fabrication_signals(fixture_repo):
    """A trace through OpenSSL, zlib and nghttp2 is what a real crash
    looks like. Those files were never in this repository, and saying so
    must not read as an accusation."""
    dossier = vet(DEPENDENCY_TRACE, fixture_repo)
    frames = verdicts(dossier, ClaimType.STACK_FRAME)

    assert frames["parse_header_line"] is Verdict.VERIFIED
    for foreign in (
        "ossl_statem_client_read_transition",
        "z_inflate",
        "nghttp2_session_mem_recv",
    ):
        assert frames[foreign] is Verdict.UNCHECKABLE, foreign

    assert dossier.strong_signals == []
    assert dossier.count(Verdict.NOT_FOUND) == 0
    assert dossier.assessment().grade == "FULLY GROUNDED"


def test_build_root_separates_our_frames_from_dependency_frames(fixture_repo):
    """The discriminator is the build root: /home/build/demo/ is us,
    /home/build/openssl/ is not, even though both end in a directory we
    happen to have."""
    dossier = vet(DEPENDENCY_TRACE, fixture_repo)
    frames = verdicts(dossier, ClaimType.STACK_FRAME)
    # nghttp2's own lib/ must not read as this project's lib/
    assert frames["nghttp2_session_mem_recv"] is Verdict.UNCHECKABLE


FABRICATED_TRACE = """\
# Overflow in priority handling

```
==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x55a1 in sanitize_priority_frame /home/build/demo/src/priority.c:88
    #1 0x55a2 in parse_header_line /home/build/demo/src/http.c:15
```
"""


def test_fabricated_frame_under_our_build_root_is_still_caught(fixture_repo):
    """The counterpart: once a frame shares the build root of frames that
    do resolve, it is claiming to be our code and gets graded."""
    dossier = vet(FABRICATED_TRACE, fixture_repo)
    frames = verdicts(dossier, ClaimType.STACK_FRAME)
    assert frames["parse_header_line"] is Verdict.VERIFIED
    assert frames["sanitize_priority_frame"] is Verdict.NOT_FOUND
    assert len(dossier.strong_signals) == 1


POC_WITH_FILENAME_HEADER = """\
# Segfault in header parsing

Proof of concept - save this and run it to reproduce:

```python
# poc.py
import socket
sock = socket.create_connection(("localhost", 8080))
sock.sendall(b"GET / HTTP/1.1\\r\\n" + b"X-A: b\\r\\n" * 100000)
print(sock.recv(1024))
```
"""


def test_poc_with_filename_comment_is_never_graded(fixture_repo):
    """A leading '# poc.py' names the reporter's own attachment. Grading
    it against the tree would guarantee a NOT FOUND on code that was
    never claimed to be ours."""
    dossier = vet(POC_WITH_FILENAME_HEADER, fixture_repo)
    quoted = [
        f for f in dossier.findings if f.claim.type is ClaimType.QUOTED_CODE
    ]
    assert quoted == []
    assert dossier.strong_signals == []
    assert any("PoC" in n for n in dossier.notes)


def test_quote_with_source_filename_comment_is_still_graded(fixture_repo):
    """The fix must not disable legitimate quote detection: a block
    headed '// src/http.c' really is quoting the tree."""
    text = """\
Here is the current implementation:

```c
// src/http.c
static int parse_header_line(struct request *req, const char *line, size_t len)
{
    if (len > MAX_HEADER)
        return -1;
    req->header_count++;
}
```
"""
    dossier = vet(text, fixture_repo)
    quoted = [
        f for f in dossier.findings if f.claim.type is ClaimType.QUOTED_CODE
    ]
    assert len(quoted) == 1
    assert quoted[0].verdict is Verdict.VERIFIED


def test_reformatted_quote_is_a_mismatch_not_a_fabrication(fixture_repo):
    """A reporter who re-indents code they copied is sloppy, not lying.
    Partial matches must land on MISMATCH, which is not a strong signal."""
    text = """\
The relevant code from src/http.c:

```c
static int parse_header_line(struct request *req, const char *line, size_t len)
{
        if (len > MAX_HEADER)   /* reindented by the reporter */
                return -1;
        req->header_count++;
}
```
"""
    dossier = vet(text, fixture_repo)
    quoted = [
        f for f in dossier.findings if f.claim.type is ClaimType.QUOTED_CODE
    ]
    assert len(quoted) == 1
    assert quoted[0].verdict is not Verdict.NOT_FOUND
    assert not quoted[0].is_strong_signal


def test_vague_report_is_not_an_accusation(fixture_repo):
    dossier = vet(
        "Your software has a serious remote code execution flaw. "
        "Please pay a bounty and I will disclose the details.",
        fixture_repo,
    )
    assert dossier.findings == []
    assert dossier.assessment().grade == "NO CHECKABLE CLAIMS"


def test_third_party_version_is_not_our_release_tag(fixture_repo):
    """"Tested on Ubuntu 22.04" is an environment note. Checking it
    against this project's tags would report it as a nonexistent
    version."""
    dossier = vet(
        "Tested on Ubuntu 22.04 with OpenSSL 3.0.2, reproduced on 1.0.0.",
        fixture_repo,
    )
    versions = verdicts(dossier, ClaimType.VERSION)
    assert versions["22.04"] is Verdict.UNCHECKABLE
    assert versions["1.0.0"] is Verdict.VERIFIED
    assert dossier.count(Verdict.NOT_FOUND) == 0


def test_copied_line_number_gutters_do_not_break_quote_matching(fixture_repo):
    """Copying from a blob view brings the line numbers along. That is
    not the reporter quoting code we do not have."""
    text = """\
The relevant code from src/http.c:

```c
  14  static int parse_header_line(struct request *req, const char *line, size_t len)
  16      if (len > MAX_HEADER)
  17          return -1;
  18      req->header_count++;
```
"""
    dossier = vet(text, fixture_repo)
    quoted = [
        f for f in dossier.findings if f.claim.type is ClaimType.QUOTED_CODE
    ]
    assert len(quoted) == 1
    assert quoted[0].verdict is Verdict.VERIFIED


def test_patch_that_creates_a_file_is_not_a_citation(fixture_repo):
    """A suggested fix adding a new file is a proposal, not a claim that
    the file already exists."""
    text = """\
Suggested fix - add a bounds helper:

```diff
--- /dev/null
+++ b/src/bounds.c
@@ -0,0 +1,3 @@
+int bounded(size_t len) {
+    return len < MAX_HEADER;
+}
```
"""
    dossier = vet(text, fixture_repo)
    files = verdicts(dossier, ClaimType.FILE)
    assert "src/bounds.c" not in files
    assert dossier.count(Verdict.NOT_FOUND) == 0


def test_source_file_named_history_c_is_not_documentation(fixture_repo):
    from vulnvet.verify import _is_doc_path

    assert not _is_doc_path("src/history.c")
    assert not _is_doc_path("lib/changes.cpp")
    assert _is_doc_path("CHANGELOG.md")
    assert _is_doc_path("docs/NEWS")


def test_one_bad_citation_among_many_good_ones_is_not_severe(fixture_repo):
    """Escalation should need a pattern, not a single slip."""
    text = """\
`parse_header_line()` in `src/http.c` and `checked_alloc()` in
`lib/util.c` are both involved; see src/http.c:15, src/http.c:18,
lib/util.c:8 and README.md. One made-up name: `frobnicate_widget()`.
"""
    dossier = vet(text, fixture_repo)
    assert len(dossier.strong_signals) == 1
    assert dossier.assessment().grade == "PARTIAL GROUNDING"


SUBMODULE_REPORT = """\
The bug is in `dep_parse_header()` in `third_party/dep/src/parser.c`,
specifically at third_party/dep/src/parser.c:2, and the file
third_party/dep/src/parser.c is vendored.
"""


def test_submodule_citations_are_unverifiable_not_false(submodule_repo):
    """A submodule's contents are not in this repository. Citing a file
    inside one is something vulnvet cannot check, not something wrong."""
    dossier = vet(SUBMODULE_REPORT, submodule_repo, rev="HEAD")
    assert dossier.findings, "expected claims to be extracted"
    for finding in dossier.findings:
        assert finding.verdict is Verdict.UNCHECKABLE, finding
        assert "submodule" in finding.evidence
    assert dossier.count(Verdict.NOT_FOUND) == 0
    assert dossier.strong_signals == []
