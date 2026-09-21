from vulnvet.claims import Claim, ClaimType, Verdict
from vulnvet.gitrepo import Repo, _normalize_version_text
from vulnvet.verify import Verifier


def make_verifier(fixture_repo, rev="v1.0.0"):
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev(rev)
    assert sha
    return Verifier(repo, sha, display=rev)


def test_normalize_version_text():
    assert _normalize_version_text("v1.2.3") == "1.2.3"
    assert _normalize_version_text("curl-8_9_0") == "8.9.0"
    assert _normalize_version_text("release-2.1") == "2.1"
    assert _normalize_version_text("nonsense") == ""


def test_real_symbol_verified(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.SYMBOL, "parse_header_line"))
    assert f.verdict is Verdict.VERIFIED
    assert "src/http.c" in f.evidence


def test_fabricated_symbol_not_found(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.SYMBOL, "ngtcp2_http3_handle_priority_frame"))
    assert f.verdict is Verdict.NOT_FOUND
    assert f.is_strong_signal


def test_wrong_case_symbol_is_mismatch(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.SYMBOL, "Parse_Header_Line"))
    assert f.verdict is Verdict.MISMATCH


def test_real_file_verified(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.FILE, "src/http.c", extra={"path": "src/http.c"}))
    assert f.verdict is Verdict.VERIFIED


def test_wrong_directory_is_mismatch_with_hint(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.FILE, "core/http.c", extra={"path": "core/http.c"}))
    assert f.verdict is Verdict.MISMATCH
    assert "src/http.c" in (f.suggestion or "")


def test_fabricated_file_not_found(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(ClaimType.FILE, "lib/vquic/ngtcp2.c", extra={"path": "lib/vquic/ngtcp2.c"})
    )
    assert f.verdict is Verdict.NOT_FOUND


def test_file_line_beyond_eof_is_mismatch(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.FILE_LINE,
            "src/http.c:5000",
            extra={"path": "src/http.c", "line": 5000},
        )
    )
    assert f.verdict is Verdict.MISMATCH
    assert "only" in f.evidence


def test_file_line_in_range_shows_the_line(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.FILE_LINE,
            "src/http.c:18",
            extra={"path": "src/http.c", "line": 18},
        )
    )
    assert f.verdict is Verdict.VERIFIED
    assert "reads:" in f.evidence


def test_absolute_build_path_resolves(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.STACK_FRAME,
            "parse_header_line",
            extra={
                "function": "parse_header_line",
                "path": "/build/demo/src/http.c",
                "line": 15,
            },
        )
    )
    assert f.verdict is Verdict.VERIFIED


def test_fabricated_frame_not_found(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.STACK_FRAME,
            "curl_mime_free_ex",
            extra={
                "function": "curl_mime_free_ex",
                "path": "/build/demo/src/http.c",
                "line": 99,
            },
        )
    )
    assert f.verdict is Verdict.NOT_FOUND


def test_libc_frame_is_uncheckable(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.STACK_FRAME,
            "__libc_start_main",
            extra={
                "function": "__libc_start_main",
                "path": "/usr/src/glibc/csu/libc-start.c",
                "line": 308,
            },
        )
    )
    assert f.verdict is Verdict.UNCHECKABLE


def test_quoted_code_real_lines_verified(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.QUOTED_CODE,
            "quoted source (3 lines sampled)",
            extra={
                "lines": [
                    "static int parse_header_line(struct request *req, const char *line, size_t len)",
                    "if (len > MAX_HEADER)",
                    "req->header_count++;",
                ],
                "hint_path": "src/http.c",
                "origin": "quote",
            },
        )
    )
    assert f.verdict is Verdict.VERIFIED


def test_quoted_code_fabricated_not_found(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.QUOTED_CODE,
            "quoted source (3 lines sampled)",
            extra={
                "lines": [
                    "int sanitize_priority_frame(frame_ctx *ctx)",
                    "ctx->weight = frame->weight * 256;",
                    "return apply_priority_update(ctx);",
                ],
                "hint_path": "src/http.c",
                "origin": "quote",
            },
        )
    )
    assert f.verdict is Verdict.NOT_FOUND
    assert f.is_strong_signal


def test_quoted_code_too_few_lines_uncheckable(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.QUOTED_CODE,
            "quoted source (1 lines sampled)",
            extra={"lines": ["req->header_count++;"], "origin": "quote"},
        )
    )
    assert f.verdict is Verdict.UNCHECKABLE


def test_version_matches_tag(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.VERSION, "1.0.0", extra={"role": "affected"}))
    assert f.verdict is Verdict.VERIFIED
    assert "v1.0.0" in f.evidence


def test_version_unknown_not_found(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.VERSION, "9.9.9", extra={"role": "affected"}))
    assert f.verdict is Verdict.NOT_FOUND
    assert f.suggestion


def test_version_range_inverted_is_flagged(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.VERSION,
            "1.1.0 .. 1.0.0",
            extra={"role": "range", "start": "1.1.0", "end": "1.0.0"},
        )
    )
    assert f.verdict is Verdict.MISMATCH
    assert "inverted" in f.evidence


def test_commit_exists(fixture_repo, fixture_head_sha):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.COMMIT, fixture_head_sha[:12]))
    assert f.verdict is Verdict.VERIFIED


def test_commit_missing_not_found(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.COMMIT, "deadbeefdeadbeefdeadbeef"))
    assert f.verdict is Verdict.NOT_FOUND


def test_future_cve_is_mismatch(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.CVE, "CVE-2099-1234", extra={"year": 2099}))
    assert f.verdict is Verdict.MISMATCH


def test_valid_cve_is_uncheckable(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.CVE, "CVE-2024-1234", extra={"year": 2024}))
    assert f.verdict is Verdict.UNCHECKABLE


def test_symbol_only_in_docs_is_mismatch(fixture_repo, tmp_path):
    # Add a symbol that exists only in README.md at a new commit.
    import subprocess

    subprocess.run(
        ["git", "-C", fixture_repo, "log", "-1"], check=True, capture_output=True
    )
    v = make_verifier(fixture_repo, rev="v1.1.0")
    # "demo" appears only in README.md ("# demo project")
    f = v.verify(Claim(ClaimType.SYMBOL, "demo_project_notes"))
    assert f.verdict is Verdict.NOT_FOUND  # sanity: truly absent stays NOT_FOUND


def test_excluded_report_cannot_corroborate_itself(fixture_repo):
    repo = Repo(fixture_repo)
    sha = repo.resolve_rev("v1.0.0")
    # "parse_header_line" exists in src/http.c; excluding that file makes
    # the only real occurrences invisible, as self-exclusion would for a
    # committed report file.
    v = Verifier(repo, sha, display="v1.0.0", exclude_paths=["src/http.c"])
    f = v.verify(Claim(ClaimType.SYMBOL, "parse_header_line"))
    assert f.verdict is Verdict.NOT_FOUND


def test_bare_document_reference_is_uncheckable(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.FILE, "report.md", extra={"path": "report.md"}))
    assert f.verdict is Verdict.UNCHECKABLE
    assert "attached document" in f.evidence


def test_doc_path_with_directory_is_still_checked(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(ClaimType.FILE, "docs/SECURITY.md", extra={"path": "docs/SECURITY.md"})
    )
    assert f.verdict is Verdict.NOT_FOUND


def test_definition_site_prefers_source_over_docs(fixture_repo):
    v = make_verifier(fixture_repo)
    # README.md contains "# demo project"; source contains the real code.
    f = v.verify(Claim(ClaimType.SYMBOL, "checked_alloc"))
    assert f.verdict is Verdict.VERIFIED
    assert "lib/util.c" in f.evidence


def test_symbol_in_wrong_file_is_mismatch(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.SYMBOL,
            "parse_header_line",
            extra={"style": "call", "in_file": "lib/util.c"},
        )
    )
    assert f.verdict is Verdict.MISMATCH
    assert "never appears in lib/util.c" in f.evidence
    assert "src/http.c" in (f.suggestion or "")


def test_symbol_in_right_file_is_verified(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.SYMBOL,
            "parse_header_line",
            extra={"style": "call", "in_file": "src/http.c"},
        )
    )
    assert f.verdict is Verdict.VERIFIED


def test_attribution_to_nonexistent_file_does_not_change_symbol_verdict(fixture_repo):
    # The bogus file gets its own NOT FOUND claim; the symbol itself is
    # real and must not be penalized twice.
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.SYMBOL,
            "parse_header_line",
            extra={"style": "call", "in_file": "does/not/exist.c"},
        )
    )
    assert f.verdict is Verdict.VERIFIED


def test_range_end_past_eof_is_a_mismatch(fixture_repo):
    """Checking only the start graded "src/http.c:1-9000" VERIFIED
    against a file of a few dozen lines."""
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.FILE_LINE,
            "src/http.c:1-9000",
            extra={"path": "src/http.c", "line": 1, "end_line": 9000},
        )
    )
    assert f.verdict is Verdict.MISMATCH
    assert "1-9000" in f.evidence


def test_range_inside_the_file_verifies(fixture_repo):
    v = make_verifier(fixture_repo)
    f = v.verify(
        Claim(
            ClaimType.FILE_LINE,
            "src/http.c:1-5",
            extra={"path": "src/http.c", "line": 1, "end_line": 5},
        )
    )
    assert f.verdict is Verdict.VERIFIED
    assert "src/http.c:1-5" in f.evidence


def test_one_tag_still_confirms_the_release_it_names(tmp_path):
    """A project at its first release - or the shallow single-tag clone
    the quickstart makes - was told its own tag could not be checked,
    and blamed for a "shallow or tagless clone" it did not have."""
    import subprocess

    path = tmp_path / "onetag"
    path.mkdir()
    for args in (
        ["init", "-q"],
        ["config", "user.email", "test@example.invalid"],
        ["config", "user.name", "Test"],
        ["config", "commit.gpgsign", "false"],
        ["config", "tag.gpgsign", "false"],
    ):
        subprocess.run(["git", "-C", str(path), *args], check=True,
                       capture_output=True)
    (path / "a.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "i"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "tag", "v1.0.0"], check=True,
                   capture_output=True)

    repo = Repo(str(path))
    v = Verifier(repo, repo.resolve_rev("v1.0.0"), display="v1.0.0")
    hit = v.verify(Claim(ClaimType.VERSION, "1.0.0", extra={"role": "affected"}))
    assert hit.verdict is Verdict.VERIFIED

    # The negative direction is the one a single tag cannot answer.
    miss = v.verify(Claim(ClaimType.VERSION, "9.9.9", extra={"role": "affected"}))
    assert miss.verdict is Verdict.UNCHECKABLE
    assert "shallow" not in miss.evidence


def test_a_markdown_heading_is_not_token_pasting(fixture_repo):
    """`##` matched every Markdown heading, so nearly every project was
    told its missing symbols might be preprocessor-generated."""
    v = make_verifier(fixture_repo)
    f = v.verify(Claim(ClaimType.SYMBOL, "totally_invented_symbol"))
    assert f.verdict is Verdict.NOT_FOUND
    assert not (f.suggestion and "token pasting" in f.suggestion)


def test_real_token_pasting_still_earns_the_caveat(tmp_path):
    import subprocess

    path = tmp_path / "pasted"
    path.mkdir()
    for args in (
        ["init", "-q"],
        ["config", "user.email", "test@example.invalid"],
        ["config", "user.name", "Test"],
    ):
        subprocess.run(["git", "-C", str(path), *args], check=True,
                       capture_output=True)
    (path / "macros.h").write_text(
        "#define MAKE_FN(name) int curl_##name##_handler(void)\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "i"],
                   check=True, capture_output=True)

    repo = Repo(str(path))
    v = Verifier(repo, repo.resolve_rev("HEAD"), display="HEAD")
    f = v.verify(Claim(ClaimType.SYMBOL, "curl_socket_handler"))
    assert f.verdict is Verdict.NOT_FOUND
    assert "token pasting" in (f.suggestion or "")


def test_an_unresolvable_rev_says_which_problem_it_is(fixture_repo):
    """One dead-end sentence served "you typed it wrong", "your clone is
    shallow" and "this project does not tag", and suggested nothing."""
    import pytest
    from vulnvet.gitrepo import GitError
    from vulnvet.verify import build_dossier

    with pytest.raises(GitError) as excinfo:
        build_dossier("<test>", Repo(fixture_repo), "9.9.9", [], [])
    message = str(excinfo.value)
    assert "v1.0.0" in message or "v1.1.0" in message
    assert "git tag -l" in message


def test_a_tilde_repo_path_is_expanded(fixture_repo, monkeypatch):
    """Nothing expands "~" for a caller passing repo_path to the library,
    and git is spawned without a shell - so the documented example could
    not run."""
    import os

    parent, name = os.path.split(fixture_repo.rstrip("/"))
    monkeypatch.setenv("HOME", parent)
    monkeypatch.setenv("USERPROFILE", parent)  # Windows
    repo = Repo(os.path.join("~", name))
    assert repo.resolve_rev("v1.0.0")
