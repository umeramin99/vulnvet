# Code of conduct

This project exists because maintainers were being buried in
vulnerability reports that cited code which does not exist. Its issue
tracker is therefore a place where people discuss reports being wrong,
sometimes badly wrong. That makes the line between *this citation is
false* and *you are a liar* the one worth holding, and it is what most
of this document is about.

## The short version

Be accurate, and be kind to people while being unsparing about claims.

## What that means here

**Say what is false, not who is lying.** "This symbol does not appear at
that revision" is a finding. "This is AI slop and you should be banned"
is not a finding, and vulnvet itself will never say it — the dossier
tells you it cannot know who or what wrote a report. Hold contributors
to the same standard as the tool.

**Give the reporter the correction first.** A wrong version, a typo, a
renamed file and a fabrication all look the same in a grep. Assume the
first three until the evidence rules them out.

**Do not paste real reporters' reports into issues.** A bug report about
a false accusation needs the citation that misgraded, the repository and
the revision — not someone's name, their email, or a report they sent
privately. Redact before you paste, and see
[SECURITY.md](SECURITY.md) for anything that would be a vulnerability in
vulnvet itself.

**Disagree with the evidence, not the person.** If you think a verdict is
wrong, the fastest route is a report, a repository and a revision that
reproduce it. That is the most valuable contribution this project takes,
and it is welcome from anyone.

Beyond that, the ordinary expectations apply: no harassment, no personal
attacks, no demeaning comments about who someone is. Disruptive conduct,
sustained bad faith, or targeting an individual will get comments removed
and, if it continues, the person blocked.

## Scope

This applies in the issue tracker, pull requests, commit messages,
discussions, and anywhere someone is representing the project.

## Reporting

Raise it with the maintainer through
[a private security advisory](https://github.com/umeramin99/vulnvet/security/advisories/new)
if it involves details that should not be public, or by opening an issue
if it does not. Reports are handled by the maintainer, who will say what
they intend to do about it.

## Attribution

This is deliberately specific to this project rather than an adoption of
the [Contributor Covenant](https://www.contributor-covenant.org). If you
would rather read a general-purpose code of conduct, that one is good.
