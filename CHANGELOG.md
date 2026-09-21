# Changelog

Notable changes to vulnvet. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

Three things here are consumer-visible contracts, and a change to any of
them is a breaking change worth a major bump: the **verdict names**
(`VERIFIED`, `NOT FOUND`, `MISMATCH`, `UNCHECKABLE`), the **grade** set
the GitHub Action exposes, and the **exit codes** (`0` grounded, `1` a
claim failed to ground, `2` usage error).

A verdict getting *fairer* — a claim that used to be `NOT FOUND` coming
back `MISMATCH` or `VERIFIED` because the check got smarter — is not a
breaking change. It is the point of the project, and those are listed
under Fixed.

## [Unreleased]

### Fixed

- A quote of real code that the reporter reformatted on its way into a
  ticket is no longer called a fabrication. The exact search misses when
  a mail client re-wraps a signature or a formatter changes the spacing
  inside a line; when every sampled line misses at once, the quote is
  now compared again with whitespace removed, and code that proves to be
  the project's own is a `MISMATCH` that names the file it matched.
  `NOT FOUND` is reserved for a quote absent either way.
- The GitHub Action no longer replaces the caller's Python. It installs
  into a throwaway virtualenv under `RUNNER_TEMP` instead of running
  `setup-python`, which inside a composite action changed `PATH` for
  every later step in the job.
- The GitHub Action no longer writes `vulnvet.json` into the caller's
  checked-out repository, where a later `git add -A` would commit it.
- The source distribution ships `docs/`, so the test suite it also ships
  passes from an unpacked tarball.

### Changed

- The package declares its version in one place (`vulnvet.__version__`),
  and carries a PEP 561 `py.typed` marker so its annotations are visible
  to type checkers.

## [0.1.0] - 2026-09-21

First public release.

### Added

- Claim extraction for symbols, stack frames, quoted code, `file:line`
  references and ranges, file paths, versions, commits and CVE IDs, from
  Markdown, plain text or an email-quoted report.
- Mechanical grading of every claim against a pinned git revision, with
  concrete evidence printed for each verdict and no model in the loop.
- Text, Markdown and JSON output; a GitHub composite Action; and a
  library API (`from vulnvet import vet`).
- A regression suite for the two failure modes that matter: honest
  reports graded as fabrications, and fabricated reports getting through.

### Fixed

Everything below was a live false accusation found by adversarial review
before the first release, and each has a test that fails without its fix.

- `Owner.member` citations — `Engine._run_query()`, the ordinary way a
  Python, Java, JavaScript or Ruby report names a method — were graded
  as one literal string, found nowhere, and reported as fabrications.
- Code the checkout has but the pinned revision does not (uncommitted
  work, or a newer branch) was reported missing rather than named.
- Stack frames into dependencies, libc and build directories were
  attributed to the project being checked.
- Reporter-supplied proof-of-concept code was graded as if the report
  claimed it came from the codebase.
- `affects everything prior to 1.2.0` pointed the maintainer at 1.2.0,
  the release that fixed the bug.
- A repository with a single version tag was told its own tag could not
  be checked.

### Security

- Report text is treated as hostile input: it cannot reach `git` as a
  command-line option, cannot inject escape sequences into the dossier
  to forge a verdict line, cannot corrupt the Markdown table, and cannot
  hang the tool. Each property has a test that fails when its guard is
  removed.

[Unreleased]: https://github.com/umeramin99/vulnvet/compare/main...HEAD
[0.1.0]: https://github.com/umeramin99/vulnvet/releases/tag/v0.1.0
