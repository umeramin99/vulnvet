<!-- Keep whichever part fits; delete the rest. -->

## What this changes

<!-- One or two sentences. If it changes a verdict, say which claim goes
     from what to what, and why that is more accurate. -->

## Evidence

<!-- For a verdict change, paste the before and after. A report, a
     repository and a revision someone else can re-run is worth more
     than a description of the behaviour. -->

```console
$ vulnvet report.md --repo … --rev …
```

## Checklist

- [ ] `python -m pytest` passes.
- [ ] New behaviour has a test, and I checked it **goes red when the fix
      is removed**. A test that passes either way is worse than useless —
      an earlier option-injection test did exactly that.
- [ ] If this makes a verdict harsher, there is a test in
      `tests/test_false_accusation.py` showing an honest report is still
      not accused.
- [ ] If this makes a verdict gentler, there is a test in
      `tests/test_evasion.py` showing a fabricated report still doesn't
      get through.
- [ ] Ambiguity resolves to `UNCHECKABLE`, never to an accusation.
- [ ] Every verdict states evidence a maintainer can re-derive by hand.
- [ ] Documented numbers and names still match the code
      (`tests/test_docs_match_code.py` checks the ones it can).

<!-- The design rules these come from are in CONTRIBUTING.md. The one
     that catches people out: escalation needs a pattern — one bad
     citation among many good ones is a correction to ask for, not an
     accusation. -->
