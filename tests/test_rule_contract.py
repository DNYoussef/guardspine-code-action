"""PHASE 3 GATE: one normalised rule contract for both consumers.

Written before the implementation, by the auditor.

A rubric has two consumers with different capabilities, and the code has been
pretending they are one. The regex evaluator can only enforce a rule that
compiles. The reviewer models can judge a rule expressed in words. Calling both
"the same rules" made every one of these true at once:

  enabled: false        the rule is enforced AND shown. Disabling does nothing.
  no pattern            dropped entirely, so a control a model could judge is
                        never put in front of the model
  invalid pattern       dropped with a warning, silently shrinking the policy
  exceptions            honoured by the evaluator, invisible to the models, so
                        they flag files the policy excludes
  named packs           the prompt still says "For DEFAULT compliance"

All five reproduced against the code this gate was written on.

THE CONTRACT. Two eligibilities, named separately, on one normalised rule:

  evaluator_eligible    a usable pattern -- the regex engine can enforce it
  reviewer_eligible     the rule says something a model can judge

  valid pattern    -> both
  no pattern       -> reviewer only. This is a semantic control, not a mistake.
  invalid pattern  -> NEITHER, and loudly. A typo must not be laundered into
                      "the model will handle it" -- that would turn a broken
                      config into a silent downgrade, which is the failure mode
                      this product exists to oppose.
  enabled: false   -> neither

Anything the models are shown but the evaluator cannot enforce must be
described honestly, because "the regex evaluator still enforces all of them"
stops being true the moment reviewer-only rules exist.
"""

import sys
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from src.risk_classifier import RiskClassifier
from src.rubric_context import format_rubric_context


def _rubric(rules, name="testpack"):
    path = Path(tempfile.mkdtemp()) / f"{name}.yaml"
    path.write_text(
        yaml.dump({"name": name, "version": "1.0", "rules": rules}), encoding="utf-8",
    )
    return RiskClassifier(rubric=name, rubric_path=path, rubric_explicit=True)


def _enforced(rc) -> list[str]:
    """Rule ids the regex evaluator will actually run."""
    return [r["id"] for r in rc.rubric_rules]


def _shown(rc) -> str:
    return format_rubric_context(rc.rubric_prompt_packs())


VALID = {"id": "VALID-1", "severity": "high", "name": "No secrets",
         "description": "Credentials must not be committed", "patterns": ["api_key"]}
SEMANTIC = {"id": "SEM-1", "severity": "high", "name": "Separation of duties",
            "description": "The author of a change cannot be its sole approver"}
DISABLED = {"id": "OFF-1", "severity": "high", "name": "Retired control",
            "description": "No longer in force", "enabled": False,
            "patterns": ["password"]}
BROKEN = {"id": "BAD-1", "severity": "high", "name": "Typo",
          "description": "Someone fat-fingered the regex", "patterns": ["[unclosed"]}


# ---------------------------------------------------------------------------
# enabled: false must mean disabled -- to both consumers
# ---------------------------------------------------------------------------

def test_a_disabled_rule_is_not_enforced():
    rc = _rubric([VALID, DISABLED])
    assert "OFF-1" not in _enforced(rc), "a disabled rule is still being enforced"


def test_a_disabled_rule_is_not_shown_to_the_models():
    rc = _rubric([VALID, DISABLED])
    assert "OFF-1" not in _shown(rc), "a disabled rule is still presented as policy"


# ---------------------------------------------------------------------------
# The two eligibilities
# ---------------------------------------------------------------------------

def test_a_semantic_rule_reaches_the_models():
    """A control expressed in words is exactly what a reviewer model is for.
    Dropping it because regex cannot express it throws away the half of the
    rubric only the models can enforce."""
    rc = _rubric([VALID, SEMANTIC])
    assert "SEM-1" in _shown(rc), "a semantic control never reaches a reviewer"


def test_a_semantic_rule_is_not_claimed_as_enforced():
    """It must not appear in the evaluator's rule set, where its absence of a
    pattern would be a silent no-op dressed as a control."""
    rc = _rubric([VALID, SEMANTIC])
    assert "SEM-1" not in _enforced(rc)


def test_a_broken_pattern_is_not_laundered_into_a_semantic_rule():
    """The dangerous middle case. A typo that silently becomes 'the model will
    handle it' converts a broken config into a quiet downgrade."""
    rc = _rubric([VALID, BROKEN])
    assert "BAD-1" not in _enforced(rc)
    assert "BAD-1" not in _shown(rc), (
        "an invalid regex was presented to the models as if it were a "
        "deliberate semantic control"
    )


def test_a_broken_pattern_is_reported(capsys):
    rc = _rubric([VALID, BROKEN])
    assert rc.rubric_errors, "a rule silently vanished from the policy"
    assert any("BAD-1" in e for e in rc.rubric_errors)


# ---------------------------------------------------------------------------
# Exceptions -- the evaluator honours them, so the models must know
# ---------------------------------------------------------------------------

@pytest.mark.xfail(
    reason="Renderer-dependent, and deliberately deferred. Exceptions are "
           "rendered by format_rubric_context, which this repo carries as a "
           "VENDORED copy of the canonical implementation in GuardSpine, "
           "pinned byte-for-byte by a shared golden vector. Changing it here "
           "alone would break that gate; changing it correctly is a three-repo "
           "edit that belongs with phases 4-5, where the renderer is unified "
           "and published once. Flip this when that lands.",
    strict=True,
)
def test_the_models_are_told_which_files_a_rule_excludes():
    """Without this the models flag exactly the files the policy excludes, and
    a reviewer learns the findings are noise."""
    rc = _rubric([{**VALID, "exceptions": ["tests/*", "**/fixtures/**"]}])
    shown = _shown(rc)
    assert "tests/*" in shown, "the models are not told what the rule excludes"


# ---------------------------------------------------------------------------
# The prompt must not contradict itself
# ---------------------------------------------------------------------------

def test_a_named_pack_is_not_announced_as_DEFAULT():
    """The prompt said 'For DEFAULT compliance' directly above HIPAA's rules."""
    from src.analyzer import DiffAnalyzer

    rc = RiskClassifier(config_packs=["hipaa-safeguards"])
    prompt = DiffAnalyzer._build_review_prompt(
        DiffAnalyzer.__new__(DiffAnalyzer), "x = 1", [], "default", True,
        rubric_packs=rc.rubric_prompt_packs(),
    )
    assert "For DEFAULT compliance" not in prompt, (
        "the prompt announces DEFAULT while showing another pack's rules"
    )


# ---------------------------------------------------------------------------
# Truncation must not claim an enforcement that does not exist
# ---------------------------------------------------------------------------

@pytest.mark.xfail(
    reason="Same renderer, same deferral as the exceptions probe above. The "
           "note is only WRONG once reviewer-only rules are shown, which this "
           "phase introduces -- so it is recorded here rather than in the "
           "phase that will fix it, and must not be forgotten.",
    strict=True,
)
def test_truncation_does_not_claim_the_evaluator_enforces_semantic_rules():
    """The existing note says the regex evaluator still enforces everything
    omitted. That was true when only compiled rules were shown. It is false for
    reviewer-only rules, and a false reassurance is worse than none."""
    many = [dict(SEMANTIC, id=f"SEM-{i}") for i in range(200)]
    block = format_rubric_context([
        {"name": "big", "version": "1.0",
         "rules": [{"id": r["id"], "severity": "high", "name": "n",
                    "description": "d", "reviewer_only": True} for r in many]},
    ])
    if "not shown" in block:
        assert "still enforces all of them" not in block, (
            "truncation promises regex enforcement for rules regex cannot run"
        )


# ---------------------------------------------------------------------------
# What must keep working
# ---------------------------------------------------------------------------

def test_an_ordinary_rule_is_unaffected():
    rc = _rubric([VALID])
    assert "VALID-1" in _enforced(rc)
    assert "VALID-1" in _shown(rc)


def test_shipped_packs_still_load_and_enforce():
    """The whole shipped catalogue must survive normalisation."""
    rc = RiskClassifier(config_packs=["security", "hipaa-safeguards"])
    enforced = _enforced(rc)
    assert enforced, "normalisation emptied the shipped packs"
    shown = _shown(rc)
    for rule_id in enforced:
        assert rule_id in shown, f"{rule_id} is enforced but hidden from the models"
