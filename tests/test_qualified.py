"""Owner.member citations - the way most of the world names a method.

A Python, Java, JavaScript or Ruby report writes ``Engine._run_query()``.
No source line contains that string: the call site reads
``self._run_query(...)``. Grading the joined form as one identifier
returned NOT FOUND - vulnvet's strongest fabrication signal - for the
single commonest correct citation outside C.
"""

from vulnvet.claims import Claim, ClaimType, Verdict
from vulnvet.extract import extract_claims
from vulnvet.gitrepo import Repo
from vulnvet.verify import Verifier


def make_verifier(repo_path, rev="v1.0.0", excludes=None):
    repo = Repo(repo_path)
    sha = repo.resolve_rev(rev)
    assert sha
    return Verifier(repo, sha, display=rev, exclude_paths=excludes)


def symbol(name, **extra):
    return Claim(ClaimType.SYMBOL, name, extra=extra or {})


def test_real_method_on_its_real_class_is_verified(class_repo):
    v = make_verifier(class_repo)
    f = v.verify(symbol("Engine._run_query"))
    assert f.verdict is Verdict.VERIFIED
    assert "app/engine.py" in f.evidence
    assert not f.is_strong_signal


def test_invented_member_is_still_a_strong_signal(class_repo):
    """The fix must not cost the tool its teeth."""
    v = make_verifier(class_repo)
    f = v.verify(symbol("Engine.sanitize_priority_frame"))
    assert f.verdict is Verdict.NOT_FOUND
    assert f.is_strong_signal


def test_member_attributed_to_the_wrong_class_is_a_mismatch(class_repo):
    v = make_verifier(class_repo)
    f = v.verify(symbol("Renderer._run_query"))
    assert f.verdict is Verdict.MISMATCH
    assert "app/engine.py" in (f.evidence + (f.suggestion or ""))


def test_invented_owner_of_a_real_member_is_a_mismatch(class_repo):
    v = make_verifier(class_repo)
    f = v.verify(symbol("QuicSession._run_query"))
    assert f.verdict is Verdict.MISMATCH
    assert "appears nowhere" in f.evidence


def test_qualified_citation_honours_its_stated_file(class_repo):
    v = make_verifier(class_repo)
    f = v.verify(symbol("Engine._run_query", style="span", in_file="app/render.py"))
    assert f.verdict is Verdict.MISMATCH
    assert "app/render.py" in f.evidence


def test_qualified_citation_in_the_right_file_is_verified(class_repo):
    v = make_verifier(class_repo)
    f = v.verify(symbol("Engine._run_query", style="span", in_file="app/engine.py"))
    assert f.verdict is Verdict.VERIFIED


def test_member_that_survives_only_in_a_changelog_is_a_mismatch(class_repo):
    v = make_verifier(class_repo)
    f = v.verify(symbol("Engine.retired_member"))
    assert f.verdict is Verdict.MISMATCH
    assert "outside source code" in f.evidence


def test_cpp_qualified_name_still_works(class_repo):
    v = make_verifier(class_repo)
    f = v.verify(symbol("Engine::_run_query"))
    assert f.verdict is Verdict.VERIFIED


def test_module_level_function_cited_through_its_module(class_repo):
    v = make_verifier(class_repo)
    f = v.verify(symbol("engine.module_helper"))
    assert f.verdict is Verdict.VERIFIED


def test_end_to_end_one_citation_makes_one_claim(class_repo):
    """The dotted form and its bare tail are one fact, not two.

    Extracting both doubled the weight a single citation carried into
    the verdict - and, before the grader understood dotted names, turned
    one honest sentence into two strong fabrication signals.
    """
    text = "The method `Engine._run_query()` in `app/engine.py` builds SQL by hand."
    claims, _ = extract_claims(text)
    symbols = [c for c in claims if c.type is ClaimType.SYMBOL]
    assert [c.value for c in symbols] == ["Engine._run_query"]
    assert symbols[0].extra.get("in_file") == "app/engine.py"

    v = make_verifier(class_repo)
    assert v.verify(symbols[0]).verdict is Verdict.VERIFIED


def test_a_dotted_filename_is_not_a_symbol():
    """The tail decides: "txt" is an extension, "render" is a member."""
    claims, _ = extract_claims(
        "See parse_header.txt and config.yaml, then `Engine.render()`.\n"
    )
    symbols = {c.value for c in claims if c.type is ClaimType.SYMBOL}
    assert symbols == {"Engine.render"}
