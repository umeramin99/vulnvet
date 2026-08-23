# vulnvet

[![ci](https://github.com/umeramin99/Open-Source/actions/workflows/ci.yml/badge.svg)](https://github.com/umeramin99/Open-Source/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.9%2B-1f6f8b)](https://github.com/umeramin99/Open-Source/blob/main/pyproject.toml)
[![dependencies](https://img.shields.io/badge/dependencies-none-1f6f8b)](https://github.com/umeramin99/Open-Source/blob/main/pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-1f6f8b)](https://github.com/umeramin99/Open-Source/blob/main/LICENSE)

**Ground a vulnerability report's claims against the actual codebase — before you spend hours triaging it.**

📄 **[umeramin99.github.io/Open-Source](https://umeramin99.github.io/Open-Source/)** — what it does, with a real dossier you can flip between a fabricated and an honest report.

You get a report. It's confident, well-formatted, and cites `ngtcp2_http3_handle_priority_frame()` in `lib/vquic/ngtcp2.c:1042`. Disproving it means checking out the right tag, grepping for the function, opening the file, counting lines, checking whether those versions ever existed.

vulnvet does that mechanically, in about a second:

```console
$ vulnvet report.md --repo ~/src/curl --rev 8.4.0

Stack trace frames
  x [NOT FOUND  ] ngtcp2_http3_handle_priority_frame
      file /src/curl/lib/vquic/ngtcp2.c not in the tree; function
      'ngtcp2_http3_handle_priority_frame' appears nowhere in the tree at curl-8_4_0

File:line references
  x [NOT FOUND  ] lib/vquic/ngtcp2.c:1042
      no such file anywhere in the tree at curl-8_4_0
      hint: closest real file: lib/vquic/curl_ngtcp2.c

Summary
  1 verified   3 not found   3 mismatched   1 uncheckable
  SEVERE GROUNDING FAILURES
```

That's a real run against a real curl checkout. The cited function has never existed in curl.

## Why this exists

In January 2026 curl [ended its bug bounty](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/) after six years, with Daniel Stenberg writing that the project was "effectively being DDoSed" by AI-generated reports. The Python Software Foundation's security developer-in-residence [documented the same pattern](https://sethmlarson.dev/slop-security-reports) across CPython, pip, urllib3 and Requests. In March 2026 the Jazzband collective — 84 Python projects, over 150M monthly downloads — [announced it was winding down](https://jazzband.co/news/2026/03/14/sunsetting-jazzband), citing a flood of AI-generated spam pull requests.

Most countermeasures have been *policy*: honor-system checkboxes, closing the bounty, banning reporters. The technical ones aim elsewhere — [honeyslop](https://github.com/gadievron/honeyslop) plants canaries in your tree so slop scanners incriminate themselves, and [anti-slop](https://github.com/peakoss/anti-slop) scores pull requests on contributor heuristics. Both are good, and both leave the same step to you: the minutes-to-hours each maintainer burns proving that a specific confident-sounding citation refers to code that does not exist.

That step is mechanical. vulnvet does exactly that step, and nothing more.

## What it checks

vulnvet extracts every mechanically checkable claim in a report and grades each one against the git tree at a pinned revision:

| Claim | What's verified |
|---|---|
| **Symbols** — `foo_bar()`, "the function `X`" | Does the identifier appear anywhere in the tree? Is it *defined* there, or only mentioned in docs? |
| **Stack frames** — ASan / gdb traces | Does the function exist, does the file exist, is the line within the file, does that function actually appear in that file? |
| **Quoted code** — "the vulnerable code looks like this" | Do the quoted lines appear verbatim in the tree? |
| **file:line** — `src/http.c:1042` | Does the file exist, and does it have that many lines? |
| **Files** — `lib/vquic/ngtcp2.c` | Does the path exist? Is there a same-named file elsewhere (wrong directory) or a near-match (typo)? |
| **Versions** — "affects 8.1.0 through 8.4.0" | Do those versions exist as release tags? Is the range inverted? |
| **Commits** — `deadbeef` | Does that commit exist in this repository? |
| **CVE IDs** | Is the identifier well-formed and the year plausible? |

Each claim comes back as one of four verdicts:

- **VERIFIED** — the citation corresponds to the codebase. *This does not validate the vulnerability logic* — only that the reporter is describing code that exists.
- **NOT FOUND** — we looked in the right place and the cited thing isn't there. On a symbol, frame, or quoted snippet this is the strong fabrication signal.
- **MISMATCH** — partially corroborated. The function exists but not in that file; the file exists but is 400 lines and they cited line 5000; the version range runs backwards.
- **UNCHECKABLE** — we could not tell either way, and say so.

## Design principle: fail toward UNCHECKABLE

A tool that cries fabrication at an honest reporter is worse than no tool. Every ambiguity resolves toward *not accusing*:

- Reporter-supplied PoC and exploit code is **never** graded against the tree — only blocks the report claims are quoting *from* the codebase.
- Prose that merely looks like an identifier isn't extracted. `use_after_free` is vulnerability jargon, not a symbol; `Node.js` is a product, not a file.
- **A stack trace walks through whatever was linked in.** Frames naming OpenSSL, zlib or libc source are UNCHECKABLE, not fabricated. vulnvet works out which frames claim *your* code by learning the build root from the frames that do resolve: given `/home/build/curl/lib/http2.c` resolving to `lib/http2.c`, anything else under `/home/build/curl/` is yours and `/home/build/openssl/…` is not.
- A quoted snippet with fewer than three distinctive lines is too small to grade fairly, and code pasted with line-number gutters is de-guttered before matching.
- Versions attributed to something else ("tested on Ubuntu 22.04") aren't checked against your release tags. Neither are version claims in a repo with no tags.
- Paths inside submodules, and files a suggested-fix patch proposes to *create*, are not citations of things that should already exist.
- In a codebase that uses `##` token pasting, a missing symbol carries a caveat: the preprocessor can build identifiers that never appear literally.
- If the report file itself lives inside the repo, it's excluded from searches — a report must never corroborate itself.

Escalation to "characteristic of fabricated reports" needs a *pattern*: either several fabricated citations, or failures clearly outweighing what the report got right. One bad citation among many good ones is a correction to ask for, not an accusation.

The regression suite for exactly this is [`tests/test_false_accusation.py`](tests/test_false_accusation.py) — each test is a report a real person could plausibly file, asserting that vulnvet doesn't accuse them.

And the dossier says this out loud, every time:

> vulnvet grounds a report's citations against the codebase; it does not judge the vulnerability logic itself, and it cannot tell who or what wrote the report. NOT FOUND means a specific cited detail does not exist at the checked revision — give the reporter a chance to correct an honest mistake (wrong version, typo) before concluding fabrication.

**vulnvet is not an AI detector.** It cannot tell you who wrote a report. A careful human can write an ungrounded report, and a fabricated report can cite real symbols. What it tells you is narrower and more useful: *whether the specific things this report points at exist.*

## Install

```console
$ pip install vulnvet          # once published
$ pipx install vulnvet         # or isolated
```

From source:

```console
$ git clone https://github.com/umeramin99/Open-Source
$ cd Open-Source && pip install -e .
```

Requires Python 3.9+ and `git` on PATH. No other dependencies, no network access, no API keys — vulnvet runs entirely offline against a local checkout.

## Use

```console
# the common case
$ vulnvet report.md --repo ~/src/myproject --rev 8.4.0

# straight from a GitHub issue
$ gh issue view 1234 --json body -q .body | vulnvet - --repo .

# a dossier you can paste into the ticket
$ vulnvet report.md --repo . --rev v2.1.0 --format markdown -o dossier.md

# machine-readable, for your own triage tooling
$ vulnvet report.md --repo . --format json | jq '.counts.strong_signals'
```

`--rev` accepts a tag, branch, SHA, or a bare version like `8.4.0` — it's matched against your tags, so `curl-8_4_0`, `v8.4.0`, and `release-8.4.0` all resolve. Omit it and vulnvet checks HEAD and says so.

Exit codes: `0` everything checkable grounded · `1` at least one NOT FOUND or MISMATCH · `2` usage error. Use `--exit-zero` to exit 0 even when claims fail to ground (usage errors still exit 2).

### Try it on the curl example

The repo ships a fictional report in the genre that flooded curl's bounty:

```console
$ git clone --depth 1 --branch curl-8_4_0 https://github.com/curl/curl /tmp/curl
$ vulnvet examples/curl-slop-report.md --repo /tmp/curl --rev 8.4.0
```

## As a GitHub Action

Auto-vet security reports as they arrive, and post the dossier as a comment:

```yaml
name: vet security report
on:
  issues:
    types: [opened, labeled]

jobs:
  vet:
    if: contains(github.event.issue.labels.*.name, 'security')
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # vulnvet needs history and tags
      - uses: umeramin99/Open-Source@main
        id: vulnvet
        with:
          report: ${{ github.event.issue.body }}
      - uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: fs.readFileSync('${{ steps.vulnvet.outputs.dossier-path }}', 'utf8'),
            });
```

The action exposes `grade`, `strong-signals`, `not-found`, `verified`, and `dossier-path` as outputs, so you can gate on them — e.g. only comment when `strong-signals > 0`, or label the issue instead of commenting.

## Use as a library

```python
from vulnvet import vet

dossier = vet(report_text, repo_path="~/src/curl", rev="8.4.0")
print(dossier.assessment().grade)

for finding in dossier.strong_signals:
    print(finding.claim.value, "-", finding.evidence)
```

## What vulnvet deliberately does not do

- **Run the PoC.** Executing attacker-supplied code to triage it is its own security problem. Out of scope.
- **Judge exploitability.** A perfectly grounded report can describe a non-issue; an ungrounded one can stumble onto a real bug. That judgment stays with you.
- **Call an LLM.** Verdicts are mechanical and reproducible: the same report and revision always give the same dossier, and you can check every claim by hand from the evidence line.
- **Guess at fuzzy matches.** If a cited symbol resembles a real one, you get a hint, not a verdict change.

## Limitations worth knowing

- **Macro-generated and code-generated symbols** may not appear as literal text in the tree, so a legitimate citation can grade NOT FOUND. curl really does build `SSL_RSA_WITH_RC4_128_MD5` out of `SSL_##num_wo_prefix`, and no grep will find it. vulnvet flags the risk when it sees `##` in the tree, but check the evidence line before acting.
- **Grep-level symbol checking** doesn't distinguish a definition from a comment mentioning the name. Where vulnvet can spot a definition it says so.
- **Reformatted quotes** — a reporter who re-indents or line-wraps code they copied will score lower on the quoted-code check than one who pastes verbatim. That lands on MISMATCH, never on a fabrication signal.
- **Shallow clones** hide tags and old commits; vulnvet says "shallow or tagless clone?" rather than pretending. Use `fetch-depth: 0` in CI.
- **Search results are capped** at 50 hits per query, so evidence lines say "50+" rather than an exact count, and vulnvet won't assert "only in documentation" off a truncated list.
- **Padding is the obvious attack**, and it's narrowed rather than solved. Listing real filenames is free, so only claims that show the reporter actually read the code — symbols, stack frames, quoted code, `file:line` — count toward "well grounded"; those claims also keep their slots when a report exceeds the extraction budget, and anything the budget did skip is named in the dossier and blocks a clean grade. A fabricated citation is named in the summary even when the grade doesn't escalate. But someone willing to cite genuinely real symbols around a fabricated conclusion will still score well, which is why the dossier gives per-claim evidence: the counts are never the answer on their own.

[`tests/test_evasion.py`](tests/test_evasion.py) pins the evasions that used to work — padding past the claim budget to delete the fabricated claims, a `vendor/…/` prefix on a real path, a build directory named `libcurl` passing as libc, a pathless stack frame laundering an invented symbol, the word "patch" deleting a self-declared source quote, and one short fabricated line hiding inside a genuine excerpt.

vulnvet also treats the report as hostile input, because it is: report text can't reach `git` as a command-line option, can't inject ANSI escapes into the dossier to forge verdict lines, can't corrupt the markdown table, and can't hang the tool. Those properties have tests that fail when the guard is removed.

## How this was built

Most of this repository was written by an AI coding agent working under my
direction and review. The commit trailers say so, and I would rather tell you
here than have you find it there.

On this project the disclosure matters, so here is the part that actually
answers it: **vulnvet never calls a model.** Every verdict is a grep, a
`git show`, or a line count. The same report at the same revision always
produces the same dossier, and each verdict prints the evidence it came from,
so you can re-derive any of them by hand in seconds. A tool for catching
unverifiable claims would be a poor joke if you had to take its own on faith.

The constraints it was built under — fail toward `UNCHECKABLE`, never accuse on
a single bad citation, never grade the reporter's own code — are written down in
[`CONTRIBUTING.md`](CONTRIBUTING.md), and enforced in
[`tests/test_false_accusation.py`](tests/test_false_accusation.py) and
[`tests/test_evasion.py`](tests/test_evasion.py).

## Contributing

Bug reports about *false accusations* — a legitimate report vulnvet grades unfairly — are the highest-value contributions. Please include the report text and the repository/revision.

```console
$ pip install -e . pytest && python -m pytest
```

## License

MIT
