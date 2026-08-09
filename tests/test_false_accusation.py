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
