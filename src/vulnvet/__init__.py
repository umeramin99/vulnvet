"""vulnvet: ground the claims in a vulnerability report against the codebase.

Public API::

    from vulnvet import vet
    dossier = vet(report_text, repo_path=".", rev="8.9.0")
"""

from __future__ import annotations

from typing import Optional

__version__ = "0.1.0"


def vet(report_text: str, repo_path: str = ".", rev: Optional[str] = None):
    """Extract claims from *report_text* and grade them against the repo.

    Returns a :class:`vulnvet.claims.Dossier`.
    """
    from .extract import extract_claims
    from .gitrepo import Repo
    from .verify import build_dossier

    claims, notes = extract_claims(report_text)
    repo = Repo(repo_path)
    return build_dossier(
        report_path="<api>",
        repo=repo,
        rev_input=rev,
        claims=claims,
        notes=notes,
    )
