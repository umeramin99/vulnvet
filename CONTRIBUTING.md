# Contributing to vulnvet

## The contribution that matters most

**A report vulnvet grades unfairly.** If you can show a legitimate
vulnerability report that comes back with a `NOT FOUND` or `MISMATCH` it
does not deserve, that is the highest-value issue you can open. A tool
that cries fabrication at an honest reporter is worse than no tool, and
every such bug found so far has been a real design flaw rather than a
rough edge.

Please include:

- the report text (or enough of it to reproduce),
- the repository and revision, ideally something public,
- what vulnvet said and what it should have said.

The second most valuable contribution is the opposite: a **fabricated
report vulnvet clears**. Those go in `tests/test_evasion.py`.

## Running the tests

```console
$ pip install -e . pytest
$ python -m pytest
```

No network access is needed. The suite builds its own git fixtures,
including one with a real submodule.

## The test suites, and what each is for

| File | Question it answers |
|---|---|
| `test_extract.py` | Does the report say this? |
| `test_verify.py` | Is this claim true of the tree? |
| `test_cli.py` | Does the command-line contract hold? |
| `test_false_accusation.py` | Does an honest report get accused? |
| `test_evasion.py` | Does a fabricated report get through? |
| `test_untrusted_input.py` | Can report text attack the tool? |

The last three are the ones to grow. A test in `test_false_accusation.py`
should read like a report a real person could plausibly file. A test in
`test_untrusted_input.py` should **fail if you delete the guard it is
testing** — write it, then delete the guard and watch it go red. An
earlier version of the option-injection test passed either way, which
made it worse than useless.

## Design rules worth knowing before you change verdict logic

1. **Ambiguity resolves to `UNCHECKABLE`.** Never to an accusation. If
   the repository state, the parse, or the reporter's phrasing leaves
   real doubt, say so and let the maintainer judge.
2. **Evidence is the product, not the grade.** Every verdict states what
   was searched and what was found. A verdict a maintainer cannot check
   by hand from its evidence line is a bug.
3. **Never grade the reporter's own code.** Proof-of-concept and exploit
   code is not a claim about the codebase. When the surrounding text is
   ambiguous, show the block and mark it ungraded.
4. **Never claim more than the search supports.** Results are capped, so
   "appears only in documentation" is only sayable when the hit list was
   not truncated. The same applies to anything the claim budget skipped.
5. **The report is hostile input.** It cannot reach `git` as an option,
   cannot inject escape sequences into the dossier, cannot hang the tool.

## Adding a new claim type

1. Add it to `ClaimType` in `claims.py`, and decide whether it belongs in
   `STRONG_SIGNAL_TYPES` (a `NOT FOUND` here is strong evidence of
   fabrication) and `SUBSTANTIVE_TYPES` (a `VERIFIED` here means the
   reporter demonstrably read the code, not just a directory listing).
2. Extract it in `extract.py`, conservatively — dropping a borderline
   token costs less than inventing a claim the report never made.
3. Verify it in `verify.py` with a handler that returns concrete evidence
   for every branch, including the ones that decline to judge.
4. Write both tests: one where an honest report is not accused, one where
   a fabricated one does not get through.

## Style

Match the surrounding code. No dependencies beyond the standard library
and `git`; that constraint is a feature, because it is what makes every
verdict reproducible offline.
