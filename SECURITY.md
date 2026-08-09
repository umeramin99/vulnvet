# Security policy

## Reporting a vulnerability in vulnvet

Open a [GitHub security advisory](https://github.com/umeramin99/Open-Source/security/advisories/new),
or a public issue if you judge the problem low risk.

Please include the report text, the repository and revision, and what
vulnvet did versus what it should have done. A reproduction against a
public repository is ideal.

## Threat model

vulnvet reads two things: a **vulnerability report**, which is untrusted
text written by someone you do not know, and a **local git checkout**,
which is trusted. It never reaches the network.

These properties are load-bearing, and each has a test that fails when
the guard protecting it is removed:

- Report text cannot reach `git` as a command-line option or a pathspec.
  Search terms are always passed behind `-e`, paths after `--`.
- Report text cannot inject terminal control sequences into the dossier.
  A reporter must not be able to repaint vulnvet's own output and forge
  a verdict line.
- Report text cannot corrupt the markdown dossier's tables.
- Report text cannot hang the tool or exhaust memory. Identifier patterns
  are bounded, over-long lines are treated as data, and claim extraction
  has a budget.
- vulnvet never executes anything from the report. Proof-of-concept code
  is never run, and never even graded against the tree.

A finding that breaks any of these is a security bug in vulnvet. Please
report it.

## What is *not* a vulnerability in vulnvet

**Evading detection is not a vulnerability, it is a limitation** — though
it is still worth reporting as a normal issue, and
[`tests/test_evasion.py`](tests/test_evasion.py) is where fixes land.

vulnvet checks whether a report's citations correspond to real code. It
cannot determine whether a vulnerability is real, and it cannot tell who
or what wrote a report. A reporter who cites genuinely existing symbols
around a false conclusion will score well, by design: the tool is
answering a narrower question than "is this report true".

Treating a `FULLY GROUNDED` dossier as a security review would be a
misuse of the tool. It means the citations are real and the report
deserves a human read.

## Using vulnvet safely

- Run it against a local checkout you trust. It shells out to `git` in
  that repository.
- `--rev` should be the revision the report claims to be about. Checking
  a fabricated report against the wrong revision produces misleading
  results in both directions.
- Read the per-claim evidence before acting on a grade. Every verdict
  states what was searched and what was found, precisely so you never
  have to take the headline on faith.
- Give a reporter the chance to correct an honest mistake before treating
  a `NOT FOUND` as fabrication. Wrong versions and stale file paths are
  ordinary.
