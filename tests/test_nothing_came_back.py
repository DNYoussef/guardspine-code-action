"""PHASE 7 GATE: the deletions hold, and no test skips itself into green.

Written by the auditor. Audit finding #12 is not a behavioural defect -- it is
a deletion prescription. Nothing should remain of: the vendored renderer, the
duplicate vectors, AI_UNAVAILABLE_PREFIX, availability-as-a-Finding, or the
mutable _rubric_packs channel.

WHAT THIS FILE DOES NOT DO. It does not restate probes that already exist.
The renderer and the duplicate corpus are pinned by
tests/test_renderer_is_not_vendored.py, and the availability contract by
tests/test_result_contract.py. Re-asserting them here would add maintenance
and no signal. One cheap symbol sweep below catches a resurrection by name;
the behavioural guarantees stay where they were written.

WHAT IS ACTUALLY LEFT, and why each matters:

1. THE INSTANCE CHANNEL. analyze() still assigns self._rubric_packs, and
   _build_review_prompt still reaches for it through getattr when no packs are
   passed. That hidden channel is precisely why rounds 2 and 3 were blind for
   as long as they were: one builder read it, the other did not, and nothing
   made the omission visible. Threading the packs kills the special case
   outright -- afterwards a prompt built without packs CANNOT silently inherit
   them from whatever the object was last used for.

   The probe for this is behavioural, not textual. Deleting the getattr and
   leaving the attribute would pass a grep and still leak.

2. TESTS THAT SKIP BECAUSE A SIBLING REPO IS ABSENT. Two cross-verification
   tests -- a bundle built here must pass kernel verification, and a tampered
   bundle must fail it -- are the product's central claim expressed as code.
   They are gated on finding ../guardspine-kernel-py, a source checkout that
   does not exist in CI, so they have been silently skipping. Meanwhile
   guardspine-kernel==2.0.0 is a pinned, hashed dependency that IS installed
   there. The test reached for a sibling directory while the real artifact sat
   in site-packages: the same defect phase 5 removed for the renderer.

   That one is fixable and must be fixed. The golden-vector fixtures are
   genuinely unavailable in CI (they live in guardspine-spec, which is neither
   installed nor checked out), so that skip is real. It is allowlisted BY NAME
   here rather than tolerated as a class, so a new silent skip fails this gate
   instead of blending in.
"""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

# Skips that are known, justified, and deliberately not fixed. Anything else
# skipping for a missing sibling is a regression this gate must catch.
ALLOWED_SIBLING_SKIPS = {
    "test_golden_vectors.py": (
        "golden vectors live in guardspine-spec, which is neither a published "
        "package nor checked out in CI"
    ),
    "e2e_verify.py": (
        "needs a guardspine-verify executable, which the installed "
        "guardspine-kernel does not provide (it ships no console scripts). "
        "Doubly inert: the filename does not match pytest's test_*.py pattern, "
        "so the normal suite never collects it at all -- this probe only sees "
        "it because it names the file explicitly. Renaming it to "
        "test_e2e_verify.py would activate a test that then skips, which is "
        "worse than leaving it visibly dormant. Fixing it means shipping or "
        "installing the verifier, which is a decision, not a rename."
    ),
}


# ---------------------------------------------------------------------------
# 1. The instance channel is dead
# ---------------------------------------------------------------------------

def test_a_prompt_cannot_inherit_packs_from_the_object():
    """The behavioural form. Set the attribute by hand, build a prompt without
    passing packs, and require that nothing from it appears.

    A textual check would pass if someone deleted the getattr and left the
    attribute, or kept the attribute and read it under another name."""
    from src.analyzer import DiffAnalyzer

    a = DiffAnalyzer(openrouter_key="test-key", ai_review=True)
    a._rubric_packs = [{
        "name": "leaked", "version": "1.0",
        "rules": [{"id": "LEAKED-FROM-INSTANCE-STATE", "severity": "high",
                   "name": "x", "description": "y"}],
    }]

    prompt = a._build_review_prompt("x = 1", [], "default", True)
    assert "LEAKED-FROM-INSTANCE-STATE" not in prompt, (
        "a prompt built with no packs inherited them from instance state -- "
        "the hidden channel that made rounds 2 and 3 blind is still open"
    )


def test_the_getattr_fallback_is_gone():
    """The textual companion. Cheap, and it names the exact construct so the
    next reader knows what not to reintroduce."""
    src = (ROOT / "src" / "analyzer.py").read_text(encoding="utf-8")
    assert 'getattr(self, "_rubric_packs"' not in src, (
        "the instance fallback is still in _build_review_prompt"
    )
    assert "self._rubric_packs" not in src, (
        "analyze() still stashes packs on the instance; thread them instead"
    )


def test_packs_passed_explicitly_still_reach_the_model():
    """The counterweight. Removing the channel must not remove the feature."""
    from src.analyzer import DiffAnalyzer
    from src.risk_classifier import RiskClassifier

    packs = RiskClassifier(config_packs=["hipaa-safeguards"]).rubric_prompt_packs()
    a = DiffAnalyzer(openrouter_key="test-key", ai_review=True)
    prompt = a._build_review_prompt("x = 1", [], "hipaa-safeguards", True,
                                    rubric_packs=packs)
    ids = [r["id"] for p in packs for r in p["rules"]]
    assert ids
    assert all(i in prompt for i in ids), "threading lost the rules"


def test_the_single_pass_path_carries_the_rubric():
    """The hop that still relies on the hidden channel.

    analyze() threads packs into _run_deliberation (phase 6) but calls
    _run_multi_model_review WITHOUT them, so the single-pass path -- every L2
    scan that does not deliberate -- reaches the prompt builder with nothing and
    depends entirely on the getattr fallback. Kill the fallback without
    threading this hop and the rubric silently stops reaching the model.

    Driven at the review entry point rather than through analyze(), which needs
    provider/tier state that says nothing about the property under test.
    """
    import json

    from src.analyzer import DiffAnalyzer
    from src.risk_classifier import RiskClassifier

    packs = RiskClassifier(config_packs=["hipaa-safeguards"]).rubric_prompt_packs()
    a = DiffAnalyzer(openrouter_key="test-key", ai_review=True)
    a.models = [("openrouter", "model-0"), ("openrouter", "model-1")]
    a.max_models_available = 2
    # ai_enabled is computed in __init__ from the model list, so injecting
    # models afterwards leaves it stale. Existing tests avoid this by calling
    # _run_deliberation directly; going through analyze() has to set it.
    a.ai_enabled = True

    seen: list[str] = []

    def fake_call(prompt, model, *args, **kwargs):
        seen.append(prompt)
        return (json.dumps({"codeguard_review": {
            "schema_version": "codeguard.ai_review.v1", "summary": "s",
            "intent": "feature", "concerns": [],
            "risk_assessment": "approve", "confidence": 0.9,
        }}), {"model_id": str(model)})

    a._call_openrouter = fake_call
    # No instance stash anywhere in this test: if the rubric reaches the prompt
    # it did so through the argument.
    assert not hasattr(a, "_rubric_packs")
    a._run_multi_model_review("x = 1", [], "hipaa-safeguards", 2, True,
                              rubric_packs=packs)

    assert seen, "no model was called; this probe proved nothing"
    first_rule = [r["id"] for p in packs for r in p["rules"]][0]
    assert first_rule in seen[0], (
        "the single-pass review path did not carry the rubric it was given"
    )


def test_analyze_hands_the_packs_to_the_single_pass_path():
    """The companion to the probe above: the functional check passes packs in
    by hand, so it cannot see analyze() failing to pass them at all."""
    import inspect

    from src.analyzer import DiffAnalyzer

    src = inspect.getsource(DiffAnalyzer.analyze)
    call = src.split("_run_multi_model_review(")[1].split(")")[0]
    assert "rubric_packs" in call, (
        "analyze() calls _run_multi_model_review without the packs; the "
        f"single-pass path is still on the hidden channel. Call site: {call!r}"
    )


# ---------------------------------------------------------------------------
# 2. No test skips itself into green
# ---------------------------------------------------------------------------

def test_cross_verification_actually_runs():
    """The two probes that prove a bundle built here verifies under the kernel
    are the product's central claim. They must execute, not skip."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_cross_verification.py",
         "-q", "--no-header", "-p", "no:randomly", "-rs"],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    out = result.stdout + result.stderr
    assert "guardspine-kernel-py not found" not in out, (
        "cross-verification skipped on a missing sibling checkout while "
        "guardspine-kernel is installed as a pinned dependency"
    )
    assert result.returncode == 0, f"cross-verification failed:\n{out[-2000:]}"


def _files_that_can_skip_on_a_sibling() -> list[Path]:
    """Derived from the source, not hardcoded, so a NEW file that introduces a
    sibling-dependent skip is picked up without editing this gate."""
    markers = ("skipUnless", "pytest.skip", "skipif")
    sibling = ("not found", "not checked out", "ROOT.parent", "parents[1].parent",
               "guardspine-kernel-py", "guardspine-spec")
    hits = []
    for path in sorted((ROOT / "tests").glob("*.py")):
        # Never select this file. It names every marker and sibling string as a
        # literal, so it matches its own detector -- and a pytest run over it
        # re-enters this probe, which spawns pytest again, forever.
        if path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(m in text for m in markers) and any(s in text for s in sibling):
            hits.append(path)
    return hits


def test_no_new_test_skips_on_a_missing_sibling():
    """An allowlist, not a tolerance. A skip that is known and justified is
    named here; anything else skipping for a missing sibling is a regression.

    Only the files that CAN skip this way are executed -- running the whole
    suite in a subprocess to learn what it skipped costs minutes and tells us
    nothing the targeted run does not.
    """
    candidates = _files_that_can_skip_on_a_sibling()
    assert candidates, (
        "no sibling-dependent test files found -- the detector is broken, "
        "which would make this probe silently vacuous"
    )

    run = subprocess.run(
        [sys.executable, "-m", "pytest", *[str(p) for p in candidates],
         "-q", "--no-header", "-p", "no:randomly", "-rs"],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    out = run.stdout + run.stderr

    offenders = []
    for line in out.splitlines():
        if not line.startswith("SKIPPED"):
            continue
        if any(name in line for name in ALLOWED_SIBLING_SKIPS):
            continue
        offenders.append(line.strip())

    assert not offenders, (
        "tests skipped because a sibling repo was missing, and they are not in "
        f"the allowlist: {offenders}"
    )


# ---------------------------------------------------------------------------
# 3. The removed symbols have not come back
# ---------------------------------------------------------------------------

def test_the_removed_symbols_have_not_returned():
    """One sweep by name. The behavioural guarantees live in the gates that
    introduced them; this only catches a resurrection."""
    gone = [
        "AI_UNAVAILABLE_PREFIX",
        "def format_rubric_context",
    ]
    offenders = []
    for path in list(ROOT.glob("src/**/*.py")) + list(ROOT.glob("*.py")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for symbol in gone:
            if symbol in text:
                offenders.append(f"{path.relative_to(ROOT)}: {symbol}")
    assert not offenders, f"a removed symbol is back: {offenders}"
