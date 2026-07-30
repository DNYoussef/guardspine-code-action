"""Gate: one definition of "usable review", loss that is recorded, numbers that reconcile.

PR #39 fixed the provider-outage path: a crashed reviewer no longer contributes
a concern, and the raw provider error no longer reaches the pull request. Those
probes are pinned here as regressions.

Three things #39 did not cover, all found by RCA:

1. THE OTHER WAY A REVIEWER PRODUCES NOTHING. It answers, and the answer is
   rejected. analyzer.py has two predicates for "usable" and they disagree on
   exactly that case:

       _review_failed(r)     = error or parse_error or schema_error
       not r.get("error")    = provider outage only

   So a schema/parse-rejected review is counted FAILED for models_used, for
   review_coverage and for the consensus vote, and simultaneously SUCCESSFUL
   when picking ai_summary. Its rejection notice then becomes the displayed
   summary and, through risk_classifier's ai_summary fallback, an "AI concern:"
   finding. A reviewer malfunction presented as an opinion about the customer's
   code, which is the category error #39 fixed, reached by a different road.

2. TOTAL REVIEW LOSS WAS SILENT. Measured: models_used=0, coverage.complete
   False, agreement 0.0, findings 0, decision "merge". A failed reviewer emits
   no findings and the engine decides on findings alone, so zero review is
   indistinguishable from nothing wrong. Recorded now, deliberately NOT
   blocking: severity stays advisory under every profile, including strict,
   where medium+provable would be promoted to a condition.

3. THE NUMBERS DID NOT RECONCILE. "configured: 3" printed beside "used: 2,
   failed: 0". Nothing was lost (TIER_MODEL_COUNT caps L2 at two) but the log
   invites subtraction across two denominators. models_requested is computed by
   both packers, never printed, and wrong when fewer models are configured than
   the tier wants.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.analyzer import DiffAnalyzer, format_review_diagnostics  # noqa: E402
from src.decision_engine import DecisionEngine  # noqa: E402
from src.risk_classifier import RiskClassifier  # noqa: E402

PROVIDER_ERROR = (
    "Error code: 400 - {'error': {'message': 'Provider returned error', "
    "'user_id': 'user_2mc3uwnrLmhuDbozLov5njnmjfS'}}"
)


def _review(call_provider) -> dict:
    a = DiffAnalyzer.__new__(DiffAnalyzer)
    a._rubric_packs = None
    a._call_provider = call_provider
    return DiffAnalyzer._get_model_review(
        a, "openrouter", "m", "diff", [], "default", True
    )


def crashed() -> dict:
    """The reviewer never ran."""
    def boom(provider, model, prompt):
        raise RuntimeError(PROVIDER_ERROR)
    return _review(boom)


def schema_rejected() -> dict:
    """The reviewer ran and produced something unusable."""
    return _review(lambda p, m, pr: ("not json at all", {"model_id": "m"}))


def good() -> dict:
    payload = json.dumps({"codeguard_review": {
        "schema_version": "codeguard.ai_review.v1",
        "summary": "Adds a null guard to the pointer handler",
        "intent": "bugfix",
        "concerns": ["No test for the zero-size case"],
        "risk_assessment": "comment",
        "confidence": 0.8,
        "rubric_scores": {
            "security_impact": 4, "code_quality": 4, "test_coverage": 3,
            "documentation": 3, "rollback_safety": 4,
        },
    }})
    return _review(lambda p, m, pr: (payload, {"model_id": "m"}))


# ---------------------------------------------------------------------------
# Regressions from #39
# ---------------------------------------------------------------------------

def test_a_provider_outage_contributes_no_concern():
    assert crashed()["concerns"] == []


def test_the_raw_provider_error_is_never_published():
    r = crashed()
    rendered = " ".join(r["concerns"]) + " " + r["summary"]
    for secret in ("user_2mc3uwnrLmhuDbozLov5njnmjfS", "user_id", "400"):
        assert secret not in rendered, secret


def test_a_broken_reviewer_still_fails_closed():
    for r in (crashed(), schema_rejected()):
        assert r["risk_assessment"] == "request_changes"
        assert r["confidence"] == 0.0


# ---------------------------------------------------------------------------
# 1. One definition of usable
# ---------------------------------------------------------------------------

def test_both_kinds_of_broken_are_failed():
    """Baseline; if this flips, the probes below are vacuous."""
    assert DiffAnalyzer._review_failed(crashed()) is True
    assert DiffAnalyzer._review_failed(schema_rejected()) is True
    assert DiffAnalyzer._review_failed(good()) is False


def test_a_rejected_answer_does_not_become_the_ai_summary():
    """Ordered rejected-first: the picker takes the first entry passing its
    filter, so order is what makes the disagreement visible."""
    picked = DiffAnalyzer._pick_ai_summary_source([schema_rejected(), good()])
    assert picked is not None, "a usable review existed and was not picked"
    assert picked["summary"].startswith("Adds a null guard"), picked["summary"]


def test_no_usable_review_means_no_ai_summary():
    assert DiffAnalyzer._pick_ai_summary_source([schema_rejected(), crashed()]) is None


def test_a_genuine_concern_is_still_reported():
    """The fix must not launder real findings into silence."""
    picked = DiffAnalyzer._pick_ai_summary_source([good()])
    assert picked["concerns"] == ["No test for the zero-size case"]


def test_a_rejection_notice_is_not_a_concern():
    """With nothing usable there is no source, so no concerns to carry."""
    assert DiffAnalyzer._pick_ai_summary_source([schema_rejected(), crashed()]) is None


# ---------------------------------------------------------------------------
# 2. Review loss recorded, not blocking
# ---------------------------------------------------------------------------

def _coverage_findings(reviews: list[dict]):
    classifier = RiskClassifier(rubric="default")
    analysis = {
        "files_changed": 1, "lines_added": 1, "lines_removed": 0,
        "files": [{"path": "src/app.py", "additions": 1, "deletions": 0, "hunks": []}],
        "sensitive_zones": [],
        "consensus_risk": "request_changes",
        "agreement_score": 0.0,
        "review_coverage": DiffAnalyzer._review_coverage(reviews),
        "multi_model_review": {"consensus": {"combined_concerns": []}},
    }
    return classifier.classify(analysis)["findings"]


def _find(findings, rule_id):
    for f in findings:
        rid = f["rule_id"] if isinstance(f, dict) else f.rule_id
        if rid == rule_id:
            return f
    return None


def _msg(f) -> str:
    return f["message"] if isinstance(f, dict) else f.message


def test_total_review_loss_is_recorded():
    """It was silent. Zero reviewers ran and nothing said so, which reads
    identically to nothing being wrong."""
    assert _find(_coverage_findings([crashed()]), "ai-availability") is not None


def test_the_record_is_not_a_code_opinion():
    """The point of the whole change: missing evidence is its own category."""
    msg = _msg(_find(_coverage_findings([crashed()]), "ai-availability")).lower()
    assert not msg.startswith("ai concern"), msg
    assert "minority" not in msg, msg
    assert "review" in msg, msg


def test_the_record_leaks_no_provider_detail():
    msg = _msg(_find(_coverage_findings([crashed()]), "ai-availability"))
    for secret in ("user_2mc3uwnrLmhuDbozLov5njnmjfS", "user_id", "400"):
        assert secret not in msg, secret


def test_recording_it_does_not_change_the_decision():
    """Record, do not block. Advisory under EVERY profile, including strict,
    where medium+provable would be promoted to a condition.

    Goes through entrypoint's _map_findings, the same conversion production
    uses, so this tests the real path rather than a hand-built Finding.
    """
    from entrypoint import _map_findings
    findings = _map_findings(_coverage_findings([crashed()]))
    assert findings, "nothing to decide on"
    for policy in ("advisory", "standard", "strict"):
        packet = DecisionEngine(policy).decide(findings)
        assert packet.decision == "merge", f"{policy}: {packet.decision}"
        assert not packet.hard_blocks, policy
        assert not packet.conditions, policy


def test_a_complete_review_records_nothing():
    """No noise on the happy path, or the signal stops meaning anything."""
    assert _find(_coverage_findings([good(), good()]), "ai-availability") is None


def test_partial_loss_is_recorded_too():
    assert _find(_coverage_findings([good(), crashed()]), "ai-availability") is not None


# ---------------------------------------------------------------------------
# 3. Accounting that reconciles
# ---------------------------------------------------------------------------

def test_used_plus_failed_equals_attempted():
    for reviews in (
        [good(), good()],
        [good(), schema_rejected()],
        [crashed(), schema_rejected()],
        [good(), crashed(), schema_rejected()],
    ):
        used = len([r for r in reviews if not DiffAnalyzer._review_failed(r)])
        failed = len([r for r in reviews if DiffAnalyzer._review_failed(r)])
        assert used + failed == len(reviews)


def test_requested_never_exceeds_what_is_configured():
    """Measured before the fix: one model configured, one review run, and the
    payload claimed models_requested 3."""
    a = DiffAnalyzer(openrouter_key="x", model_1="openai/m1")
    a._call_provider = lambda p, m, pr: (json.dumps({"codeguard_review": {
        "schema_version": "codeguard.ai_review.v1", "summary": "s",
        "intent": "test", "concerns": [], "risk_assessment": "approve",
        "confidence": 0.9, "rubric_scores": {
            "security_impact": 4, "code_quality": 4, "test_coverage": 4,
            "documentation": 4, "rollback_safety": 4}}}), {"model_id": "m1"})
    mm = DiffAnalyzer._run_multi_model_review(a, "diff", [], "default", 3, True)
    assert mm["models_requested"] <= len(a.models)
    assert mm["models_used"] + mm["models_failed"] == mm["models_requested"]


def test_the_diagnostics_state_how_many_were_requested():
    """Without this the reader subtracts configured minus used and finds a
    reviewer that was never missing."""
    joined = "\n".join(format_review_diagnostics(
        configured=3, mmr={"models_used": 2, "models_failed": 0, "models_requested": 2},
    ))
    assert "requested: 2" in joined, joined
    assert "used: 2" in joined and "failed: 0" in joined, joined


def test_the_diagnostics_say_why_configured_and_requested_differ():
    joined = "\n".join(format_review_diagnostics(
        configured=3, mmr={"models_used": 2, "models_failed": 0, "models_requested": 2},
    ))
    assert "tier" in joined.lower(), joined


def test_the_diagnostics_flag_a_genuine_shortfall():
    """requested > used + failed means a reviewer really did vanish."""
    joined = "\n".join(format_review_diagnostics(
        configured=3, mmr={"models_used": 1, "models_failed": 0, "models_requested": 3},
    ))
    assert "unaccounted" in joined.lower(), joined
