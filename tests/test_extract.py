from vulnvet.claims import ClaimType
from vulnvet.extract import extract_claims


def claims_of(claims, ctype):
    return [c for c in claims if c.type is ctype]


def values(claims, ctype):
    return {c.value for c in claims_of(claims, ctype)}


def test_symbols_from_inline_code_and_prose():
    text = (
        "The function `ngtcp2_http3_handle_priority_frame()` mishandles "
        "priority frames. It is reached from process_incoming_frames() "
        "whenever a peer sends crafted input."
    )
    claims, _ = extract_claims(text)
    syms = values(claims, ClaimType.SYMBOL)
    assert "ngtcp2_http3_handle_priority_frame" in syms
    assert "process_incoming_frames" in syms


def test_bare_snake_case_needs_two_underscores():
    text = (
        "A classic use_after_free occurs because http_proxy handling frees "
        "the buffer, and later curl_multi_socket_action touches it."
    )
    claims, _ = extract_claims(text)
    syms = values(claims, ClaimType.SYMBOL)
    assert "curl_multi_socket_action" in syms
    # jargon and single-underscore prose tokens are not extracted
    assert "use_after_free" not in syms
    assert "http_proxy" not in syms


def test_file_and_file_line_extraction():
    text = (
        "The bug lives in lib/vquic/ngtcp2.c and is triggered at "
        "src/http.c:15. See also `docs/SECURITY.md`."
    )
    claims, _ = extract_claims(text)
    assert values(claims, ClaimType.FILE) == {
        "lib/vquic/ngtcp2.c",
        "docs/SECURITY.md",
    }
    fl = claims_of(claims, ClaimType.FILE_LINE)
    assert len(fl) == 1
    assert fl[0].extra == {"path": "src/http.c", "line": 15}


def test_file_line_survives_sentence_period():
    claims, _ = extract_claims("The overflow is at src/http.c:15.")
    fl = claims_of(claims, ClaimType.FILE_LINE)
    assert len(fl) == 1
    assert fl[0].extra["line"] == 15


def test_product_names_are_not_files_or_symbols():
    text = "This affects Node.js users and the Vue.js frontend via GitHub."
    claims, _ = extract_claims(text)
    assert not claims_of(claims, ClaimType.FILE)
    assert not claims_of(claims, ClaimType.SYMBOL)


def test_version_range_and_roles():
    text = (
        "The flaw affects versions 1.0.0 through 1.1.0. It was introduced "
        "in 0.9.2 and fixed in 1.2.0."
    )
    claims, _ = extract_claims(text)
    versions = claims_of(claims, ClaimType.VERSION)
    roles = {(c.extra.get("role"), c.value) for c in versions}
    assert ("range", "1.0.0 .. 1.1.0") in roles
    assert ("introduced", "0.9.2") in roles
    assert ("fixed", "1.2.0") in roles


def test_cve_and_commit_extraction():
    text = (
        "Tracked as CVE-2026-12345, introduced by commit deadbeefcafe. "
        "Full hash 0123456789abcdef0123456789abcdef01234567 for reference."
    )
    claims, _ = extract_claims(text)
    assert values(claims, ClaimType.CVE) == {"CVE-2026-12345"}
    commits = values(claims, ClaimType.COMMIT)
    assert "deadbeefcafe" in commits
    assert "0123456789abcdef0123456789abcdef01234567" in commits


def test_urls_do_not_leak_file_claims():
    text = (
        "See https://github.com/example/proj/blob/main/src/http.c#L15 "
        "for details."
    )
    claims, _ = extract_claims(text)
    assert not claims_of(claims, ClaimType.FILE)
    assert not claims_of(claims, ClaimType.FILE_LINE)


def test_asan_trace_block_yields_stack_frames():
    text = """\
The crash:

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x7f00 in parse_header_line /build/demo/src/http.c:15
    #1 0x7f01 in handle_request /build/demo/src/http.c:24
    #2 0x7f02 in main /build/demo/src/main.c:9
```
"""
    claims, _ = extract_claims(text)
    frames = claims_of(claims, ClaimType.STACK_FRAME)
    funcs = {c.extra["function"] for c in frames}
    assert funcs == {"parse_header_line", "handle_request"}
    frame = next(c for c in frames if c.extra["function"] == "parse_header_line")
    assert frame.extra["path"] == "/build/demo/src/http.c"
    assert frame.extra["line"] == 15


def test_poc_block_is_never_graded_as_quote():
    text = """\
Run the following PoC script to reproduce:

```python
import socket
payload = b"A" * 100000
sock = socket.create_connection(("localhost", 8080))
sock.sendall(payload)
```
"""
    claims, notes = extract_claims(text)
    assert not claims_of(claims, ClaimType.QUOTED_CODE)
    assert any("PoC" in n for n in notes)


def test_quote_marker_block_is_graded():
    text = """\
The vulnerable code in src/http.c looks like this:

```c
static int parse_header_line(struct request *req, const char *line, size_t len)
{
    if (len > MAX_HEADER)
        return -1;
    req->header_count++;
    return 0;
}
```
"""
    claims, _ = extract_claims(text)
    quotes = claims_of(claims, ClaimType.QUOTED_CODE)
    assert len(quotes) == 1
    assert quotes[0].extra["hint_path"] == "src/http.c"
    assert len(quotes[0].extra["lines"]) >= 3


def test_diff_block_yields_file_and_patch_context():
    text = """\
Suggested fix:

```diff
--- a/src/http.c
+++ b/src/http.c
@@ -14,7 +14,7 @@
 static int parse_header_line(struct request *req, const char *line, size_t len)
 {
-    if (len > MAX_HEADER)
+    if (len >= MAX_HEADER)
         return -1;
```
"""
    claims, _ = extract_claims(text)
    assert "src/http.c" in values(claims, ClaimType.FILE)
    quotes = claims_of(claims, ClaimType.QUOTED_CODE)
    assert len(quotes) == 1
    assert quotes[0].extra["origin"] == "patch"


def test_file_claim_deduped_when_file_line_exists():
    text = "The issue is in src/http.c, specifically src/http.c:15."
    claims, _ = extract_claims(text)
    assert not claims_of(claims, ClaimType.FILE)
    assert len(claims_of(claims, ClaimType.FILE_LINE)) == 1


def test_empty_report_yields_nothing():
    claims, notes = extract_claims("Hello, I found a serious bug. Pay me.")
    assert claims == []


def test_email_quoted_report_is_unwrapped():
    text = """\
> # Heap overflow in header parsing
>
> The function `parse_header_line()` in src/http.c is unbounded.
>
> ```
> ==1==ERROR: AddressSanitizer: heap-buffer-overflow
>     #0 0x7f00 in parse_header_line /build/demo/src/http.c:15
> ```
"""
    claims, notes = extract_claims(text)
    assert any("quoted text" in n for n in notes)
    frames = claims_of(claims, ClaimType.STACK_FRAME)
    assert {c.extra["function"] for c in frames} == {"parse_header_line"}
    assert "src/http.c" in values(claims, ClaimType.FILE)


def test_occasionally_quoted_fence_is_still_a_block():
    text = """\
Here is how to reproduce, per the reporter:

> Run the following PoC:
>
> ```python
> import socket
> payload = b"A" * 100000
> socket.create_connection(("localhost", 8080)).sendall(payload)
> ```

The real bug is in `parse_header_line()`.
"""
    claims, notes = extract_claims(text)
    # the quoted PoC must not be graded as if it were quoted source
    assert not claims_of(claims, ClaimType.QUOTED_CODE)
    assert "parse_header_line" in values(claims, ClaimType.SYMBOL)


def test_shell_console_block_is_not_graded():
    text = """\
Reproduce with:

```console
$ vulnvet report.md --repo curl --rev 8.4.0
$ ./configure --with-openssl && make
```
"""
    claims, _ = extract_claims(text)
    assert not claims_of(claims, ClaimType.QUOTED_CODE)
    assert not claims_of(claims, ClaimType.FILE)


def test_symbol_attributed_to_file():
    text = "The function `parse_header_line()` in `src/http.c` is unbounded."
    claims, _ = extract_claims(text)
    sym = next(c for c in claims_of(claims, ClaimType.SYMBOL))
    assert sym.value == "parse_header_line"
    assert sym.extra.get("in_file") == "src/http.c"


def test_attribution_in_plain_prose():
    text = "checked_alloc is defined in lib/util.c and never validates size."
    claims, _ = extract_claims(text)
    syms = {c.value: c.extra.get("in_file") for c in claims_of(claims, ClaimType.SYMBOL)}
    assert syms.get("checked_alloc") == "lib/util.c"


def test_attribution_ignores_product_paths():
    text = "The handler `render_component()` in Vue.js breaks."
    claims, _ = extract_claims(text)
    syms = claims_of(claims, ClaimType.SYMBOL)
    assert all(c.extra.get("in_file") is None for c in syms)


def test_line_ranges_and_permalink_positions():
    """A report cites positions in more than one notation, and dropping
    the end of a range meant a fabricated one was graded on its start."""
    claims, _ = extract_claims(
        "Range src/http.c:10-20, permalink src/http.c#L30, "
        "permalink range src/http.c#L40-L50, column src/http.c:60:8.\n"
    )
    positions = {
        c.value: (c.extra.get("line"), c.extra.get("end_line"))
        for c in claims_of(claims, ClaimType.FILE_LINE)
    }
    assert positions["src/http.c:10-20"] == (10, 20)
    assert positions["src/http.c:30"] == (30, None)
    assert positions["src/http.c:40-50"] == (40, 50)
    # a column is not a second line number
    assert positions["src/http.c:60"] == (60, None)


def test_a_backwards_range_keeps_only_its_start():
    claims, _ = extract_claims("Backwards: src/http.c:90-10.\n")
    fl = claims_of(claims, ClaimType.FILE_LINE)
    assert len(fl) == 1
    assert fl[0].extra["line"] == 90
    assert "end_line" not in fl[0].extra
