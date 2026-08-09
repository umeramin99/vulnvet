import json

import pytest

from vulnvet.cli import main

SLOP_REPORT = """\
# Critical heap overflow in HTTP priority handling

The function `sanitize_priority_frame()` in `src/priority.c` fails to
validate the weight field, affecting versions 1.0.0 through 1.1.0.

The vulnerable code in src/priority.c looks like this:

```c
int sanitize_priority_frame(frame_ctx *ctx, const uint8_t *data)
{
    ctx->weight = data[4] * WEIGHT_SCALE_FACTOR;
    return apply_priority_update(ctx, data);
}
```

Crash observed at src/http.c:5000 with this trace:

```
==999==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x7f00 in sanitize_priority_frame /build/demo/src/priority.c:88
    #1 0x7f01 in handle_request /build/demo/src/http.c:24
```
"""

GROUNDED_REPORT = """\
# Possible unbounded loop in header parsing

The function `parse_header_line()` in `src/http.c` increments
`header_count` without an upper bound. Reproduced on 1.0.0.

The relevant code in src/http.c looks like this:

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


def test_slop_report_fails_with_evidence(fixture_repo, tmp_path, capsys):
    rc = main([str_report(tmp_path, SLOP_REPORT), "--repo", fixture_repo,
               "--rev", "v1.0.0", "--no-color"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "sanitize_priority_frame" in out
    assert "NOT FOUND" in out
    assert "SEVERE GROUNDING FAILURES" in out
    # the real function in the fabricated trace still verifies
    assert "handle_request" in out


def test_grounded_report_passes(fixture_repo, tmp_path, capsys):
    rc = main([str_report(tmp_path, GROUNDED_REPORT), "--repo", fixture_repo,
               "--rev", "1.0.0", "--no-color"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "FULLY GROUNDED" in out


def test_json_output_is_machine_readable(fixture_repo, tmp_path, capsys):
    rc = main([str_report(tmp_path, SLOP_REPORT), "--repo", fixture_repo,
               "--rev", "v1.0.0", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["counts"]["strong_signals"] >= 2
    verdicts = {f["claim"]: f["verdict"] for f in payload["findings"]}
    assert verdicts.get("sanitize_priority_frame") == "NOT_FOUND"


def test_markdown_dossier_written_to_file(fixture_repo, tmp_path):
    out_file = tmp_path / "dossier.md"
    rc = main([str_report(tmp_path, SLOP_REPORT), "--repo", fixture_repo,
               "--rev", "v1.0.0", "-o", str(out_file)])
    assert rc == 1
    content = out_file.read_text()
    assert "vulnvet triage dossier" in content
    assert "❌ NOT FOUND" in content


def test_exit_zero_flag(fixture_repo, tmp_path, capsys):
    rc = main([str_report(tmp_path, SLOP_REPORT), "--repo", fixture_repo,
               "--rev", "v1.0.0", "--exit-zero", "--no-color"])
    capsys.readouterr()
    assert rc == 0


def test_bad_repo_is_usage_error(tmp_path, capsys):
    rc = main([str_report(tmp_path, SLOP_REPORT), "--repo", str(tmp_path)])
    capsys.readouterr()
    assert rc == 2


def test_bad_rev_is_usage_error(fixture_repo, tmp_path, capsys):
    rc = main([str_report(tmp_path, SLOP_REPORT), "--repo", fixture_repo,
               "--rev", "does-not-exist"])
    capsys.readouterr()
    assert rc == 2


def test_empty_report_is_usage_error(fixture_repo, tmp_path, capsys):
    empty = tmp_path / "empty.md"
    empty.write_text("   \n")
    rc = main([str(empty), "--repo", fixture_repo])
    capsys.readouterr()
    assert rc == 2


def test_stdin_report(fixture_repo, monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(GROUNDED_REPORT))
    rc = main(["-", "--repo", fixture_repo, "--rev", "v1.0.0", "--no-color"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "<stdin>" in out


def str_report(tmp_path, content):
    report = tmp_path / "report.md"
    report.write_text(content)
    return str(report)


def test_markdown_does_not_leak_local_paths(fixture_repo, tmp_path, capsys):
    rc = main([str_report(tmp_path, SLOP_REPORT), "--repo", fixture_repo,
               "--rev", "v1.0.0", "--format", "markdown"])
    out = capsys.readouterr().out
    assert rc == 1
    # the dossier is meant to be pasted publicly: no absolute paths
    assert fixture_repo not in out
    assert str(tmp_path) not in out
    assert "report.md" in out
