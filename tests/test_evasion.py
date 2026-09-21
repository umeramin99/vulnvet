"""Regression tests for ways a fabricated report escaped detection.

The companion to test_false_accusation.py. Each test here is an evasion
that worked against an earlier version: the report is fabricated and the
assertion is that vulnvet still says so. Every one was found by an
adversarial review and reproduced before being fixed.

None of this makes vulnvet unbeatable — a reporter who cites genuinely
real symbols around a false conclusion still scores well, and that is
documented. These pin the failures that were free.
"""

from vulnvet.claims import ClaimType, Verdict
from vulnvet.extract import extract_claims
from vulnvet.gitrepo import Repo
from vulnvet.verify import build_dossier


def vet(text, repo_path, rev="v1.0.0"):
    stats = {}
    claims, notes = extract_claims(text, stats)
    return build_dossier(
        "<test>", Repo(repo_path), rev, claims, notes, stats.get("dropped")
    )


def test_padding_past_the_claim_budget_cannot_delete_the_evidence(fixture_repo):
    """Prose is parsed before code blocks, so quoted code and trace frames
    sat at the tail of the claim list. Pasting a long file listing above
    them pushed every fabricated claim past the cap, and the report
    graded FULLY GROUNDED because nothing ever looked at them."""
    padding = "\n".join(f"- src/generated_{i}.c" for i in range(400))
    text = f"""\
# Overflow

Audit surface (all files reviewed):

{padding}

The vulnerable code in src/http.c looks like this:

```c
static int vquic_prio_frame_copy(struct quic_ctx *ctx, const uint8_t *src)
{{
    uint8_t scratch[64];
    size_t len = get_uint32(src + 4);
    memcpy(scratch, src + 8, len);
    return vquic_prio_dispatch(ctx, scratch, len);
}}
```

```
==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1 in vquic_prio_frame_copy /build/demo/src/vquic_prio.c:412
    #1 0x2 in parse_header_line /build/demo/src/http.c:15
```
"""
    dossier = vet(text, fixture_repo)
    kinds = {f.claim.type for f in dossier.findings}
    assert ClaimType.QUOTED_CODE in kinds, "the fabricated quote was dropped"
    assert ClaimType.STACK_FRAME in kinds, "the fabricated frame was dropped"
    assert dossier.strong_signals, "padding suppressed every strong signal"
    assert dossier.assessment().grade == "SEVERE GROUNDING FAILURES"


def test_dropped_claims_are_recorded_and_reported(fixture_repo):
    """When the budget does bite, the dossier has to say what it skipped
    rather than leave the omission invisible."""
    padding = "\n".join(f"- src/generated_{i}.c" for i in range(400))
    dossier = vet(f"# Audit\n\n{padding}\n", fixture_repo)
    assert dossier.dropped
    assert any("not checked" in n for n in dossier.notes)
    assert dossier.assessment().grade != "FULLY GROUNDED"


def test_dropped_claims_prevent_a_clean_bill_of_health():
    """The grade must never certify claims nobody looked at, even when
    everything it did look at passed."""
    from vulnvet.claims import Claim, Dossier, Finding

    ok = Finding(
        Claim(ClaimType.SYMBOL, "real_symbol"), Verdict.VERIFIED, "found"
    )
    clean = Dossier("r", "repo", "v1", "abc123", [ok])
    assert clean.assessment().grade == "FULLY GROUNDED"

    truncated = Dossier("r", "repo", "v1", "abc123", [ok], dropped={"file": 27})
    assessment = truncated.assessment()
    assert assessment.grade == "COVERAGE INCOMPLETE"
    assert "27" in assessment.summary


def test_fabricated_path_prefix_does_not_verify(fixture_repo):
    """`vendor/evil/src/http.c` ends in a real path. Accepting it made
    the dossier corroborate, and quote lines from, a path the repository
    has never contained."""
    text = (
        "The overflow is in vendor/quicfork/patched/src/http.c and the "
        "write happens at src/thirdparty/evil/lib/util.c:4.\n"
    )
    dossier = vet(text, fixture_repo)
    assert dossier.count(Verdict.VERIFIED) == 0
    for finding in dossier.findings:
        assert finding.verdict is not Verdict.VERIFIED, finding


def test_a_build_dir_named_like_libc_does_not_excuse_a_frame(fixture_repo):
    """"libc" is a substring of "libcurl", so a substring test dismissed
    every frame under /build/libcurl/ as a system library."""
    text = """\
```
#0 0x1 in totally_invented_symbol /build/libcurl/src/vquic_prio.c:412
#1 0x2 in parse_header_line /build/libcurl/src/http.c:15
```
"""
    dossier = vet(text, fixture_repo)
    frames = {
        f.claim.value: f.verdict
        for f in dossier.findings
        if f.claim.type is ClaimType.STACK_FRAME
    }
    assert frames["totally_invented_symbol"] is Verdict.NOT_FOUND
    assert dossier.strong_signals


def test_a_pathless_frame_cannot_launder_a_prose_symbol(fixture_repo):
    """A pathless frame grades UNCHECKABLE, and dedupe then deleted the
    prose SYMBOL claim that would have caught the same name - so listing
    a fabricated name once in a frame-shaped line neutralised it."""
    text = """\
The bug is in `totally_invented_symbol()`, reached from
`another_invented_symbol()` during startup.

```
    #0 0x7f0000000001 in totally_invented_symbol
    #1 0x7f0000000002 in another_invented_symbol
```
"""
    dossier = vet(text, fixture_repo)
    assert len(dossier.strong_signals) >= 2, (
        "the frame-shaped lines suppressed the prose symbol claims"
    )
    assert dossier.assessment().grade == "SEVERE GROUNDING FAILURES"


def test_one_incidental_word_cannot_delete_a_self_declared_quote(fixture_repo):
    """The proof-of-concept veto ran before the quote check, so a lead-in
    saying "the patch below shows the vulnerable code in x.c" deleted the
    block entirely and called it the reporter's own PoC."""
    text = """\
The patch below shows the vulnerable code in src/http.c:

```c
static int vquic_prio_frame_copy(struct quic_ctx *ctx, const uint8_t *src)
{
    uint8_t scratch[64];
    memcpy(scratch, src + 8, 4096);
    return vquic_prio_dispatch(ctx, scratch, 4096);
}
```
"""
    dossier = vet(text, fixture_repo)
    quoted = [
        f for f in dossier.findings if f.claim.type is ClaimType.QUOTED_CODE
    ]
    assert quoted, "the block vanished from the dossier entirely"
    assert "not graded" in quoted[0].claim.value
    assert quoted[0].verdict is Verdict.UNCHECKABLE
    # and the grade must not certify a report whose code went ungraded
    assert dossier.assessment().grade != "FULLY GROUNDED"


def test_one_inserted_line_in_a_genuine_excerpt_is_caught(fixture_repo):
    """Sampling the longest lines dropped exactly the short payload line
    an attacker inserts into an otherwise real excerpt."""
    text = """\
The relevant code from src/http.c:

```c
static int parse_header_line(struct request *req, const char *line, size_t len)
{
    if (len > MAX_HEADER)
        return -1;
    memcpy(req->scratch, line, len);
    req->header_count++;
    return 0;
}
```
"""
    dossier = vet(text, fixture_repo)
    quoted = [
        f for f in dossier.findings if f.claim.type is ClaimType.QUOTED_CODE
    ]
    assert len(quoted) == 1
    assert quoted[0].verdict is not Verdict.VERIFIED
    assert "memcpy" in quoted[0].evidence, (
        "the evidence must name the line that was not found"
    )


def test_a_symbol_only_in_release_notes_is_not_corroborated(fixture_repo):
    """Projects list every symbol they ever had in extension-less prose
    files. curl's RELEASE-NOTES made removed functions grade VERIFIED and
    get reported as "defined at RELEASE-NOTES:123"."""
    from vulnvet.verify import _is_source_path

    assert _is_source_path("lib/http.c")
    assert _is_source_path("src/parser.py")
    assert not _is_source_path("RELEASE-NOTES")
    assert not _is_source_path("docs/libcurl/symbols-in-versions")
    assert not _is_source_path("docs/KNOWN_BUGS")


def test_ignoring_whitespace_does_not_launder_an_invented_quote(fixture_repo):
    """The reflow check must not become a way through.

    Quoting one real line and inventing the rest is the obvious abuse:
    if a single normalised match were enough, "reformatted" would
    excuse any fabrication that opened with a genuine signature.
    """
    text = """\
The vulnerable code in src/http.c looks like this:

```c
static int parse_header_line(struct request *req, const char *line, size_t len) {
    ctx->weight = frame->weight * 256 ;
    return apply_priority_update(ctx) ;
    sanitize_priority_frame(ctx, len) ;
}
```
"""
    dossier = vet(text, fixture_repo)
    quoted = [
        f for f in dossier.findings if f.claim.type is ClaimType.QUOTED_CODE
    ]
    assert len(quoted) == 1
    assert quoted[0].verdict is Verdict.NOT_FOUND
    assert quoted[0].is_strong_signal


def test_a_wholly_invented_quote_is_still_a_fabrication(fixture_repo):
    text = """\
The vulnerable code in src/http.c looks like this:

```c
static int sanitize_priority_frame(struct frame_ctx *ctx, size_t weight)
{
    ctx->weight = weight * 256;
    return apply_priority_update(ctx, ctx->weight);
}
```
"""
    dossier = vet(text, fixture_repo)
    quoted = [
        f for f in dossier.findings if f.claim.type is ClaimType.QUOTED_CODE
    ]
    assert len(quoted) == 1
    assert quoted[0].verdict is Verdict.NOT_FOUND
    assert quoted[0].is_strong_signal
