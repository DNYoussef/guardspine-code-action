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

A second review of the fix for (3) found that it had traded one silence for
another, and the corrections are pinned below:

  - Making models_requested mean "attempted" did reconcile the arithmetic, by
    deleting the only record that the tier had asked for more. One reviewer
    configured against an L4 tier wanting three reported complete coverage.
    Both numbers are kept now, and coverage is judged against the ASK.
  - The AI-COVERAGE record made the caller's findings list truthy, so a total
    outage generated a SARIF document whose only result the exporter then
    removed -- zero results with executionSuccessful true, which is how code
    scanning is told to close existing alerts. An outage became an all-clear.
  - It also inflated findings_count, a documented public output customers gate
    on, so an outage changed their merge outcome.
  - "One predicate everywhere" was claimed while two call sites still used the
    narrow one: early-exit voting and evidence-bundle provenance.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.analyzer import (  # noqa: E402
    DiffAnalyzer, format_review_diagnostics, review_failed,
)
from src.decision_engine import DecisionEngine  # noqa: E402
from src.risk_classifier import RiskClassifier  # noqa: E402
from src.sarif_exporter import SARIFExporter, is_policy_finding  # noqa: E402

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


def _analysis_with(responses: list):
    """Drive analyze() end to end, so the probe covers the WIRING.

    Calling _pick_ai_summary_source directly proves only that the helper works.
    An adversarial pass reverted analyze() to the old `not r.get("error")`
    filter and every probe here still passed, which made them theater: the bug
    was never in the helper, it was in which filter the call site used.
    """
    a = DiffAnalyzer(openrouter_key="x", model_1="openai/m1", model_2="openai/m2")
    it = iter(responses)

    def call(provider, model, prompt):
        nxt = next(it)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt, {"model_id": model}

    a._call_provider = call
    result = a.analyze(
        "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n"
        "+++ b/src/app.py\n@@ -0,0 +1 @@\n+x = 1\n"
    )
    # Assert the precondition rather than trusting it. Without this the probes
    # below pass silently whenever the run degenerates to fewer reviewers than
    # the case needs -- which is how one of them survived a mutation that it
    # caught when run in isolation. A degenerate run must fail loudly, not
    # quietly agree.
    reviews = (result.multi_model_review or {}).get("reviews", [])
    assert len(reviews) == len(responses), (
        f"expected {len(responses)} reviewers, got {len(reviews)}; "
        "this probe proves nothing on a degenerate run"
    )
    return result


GOOD_JSON = json.dumps({"codeguard_review": {
    "schema_version": "codeguard.ai_review.v1",
    "summary": "Adds a null guard to the pointer handler",
    "intent": "bugfix", "concerns": ["No test for the zero-size case"],
    "risk_assessment": "comment", "confidence": 0.8,
    "rubric_scores": {"security_impact": 4, "code_quality": 4,
                      "test_coverage": 3, "documentation": 3,
                      "rollback_safety": 4},
}})


def test_a_rejected_answer_does_not_become_the_ai_summary():
    """Ordered rejected-first: the picker takes the first entry passing its
    filter, so order is what makes the disagreement visible."""
    picked = DiffAnalyzer._pick_ai_summary_source([schema_rejected(), good()])
    assert picked is not None, "a usable review existed and was not picked"
    assert picked["summary"].startswith("Adds a null guard"), picked["summary"]


def test_analyze_does_not_surface_a_rejection_notice_as_the_summary():
    """The same property, through analyze(). This is the one that fails if the
    call site regresses to the weaker filter."""
    result = _analysis_with(["not json at all", GOOD_JSON])
    summary = (result.ai_summary or {}).get("summary", "")
    assert "rejected" not in summary.lower(), summary
    assert summary.startswith("Adds a null guard"), summary


def test_analyze_leaves_no_summary_when_nothing_was_usable():
    result = _analysis_with(["not json at all", RuntimeError(PROVIDER_ERROR)])
    assert not (result.ai_summary or {}).get("summary"), result.ai_summary
    assert not (result.ai_summary or {}).get("concerns"), result.ai_summary


def test_analyze_reconciles_its_own_reviewer_counts():
    """Reads the PRODUCTION packer rather than recomputing the predicate in the
    test, which was a tautology: it asserted a definition against itself."""
    for responses in (
        [GOOD_JSON, GOOD_JSON],
        [GOOD_JSON, "not json at all"],
        [RuntimeError(PROVIDER_ERROR), "not json at all"],
    ):
        mmr = _analysis_with(responses).multi_model_review
        assert mmr["models_used"] + mmr["models_failed"] == mmr["models_requested"], mmr


def test_no_usable_review_means_no_ai_summary():
    assert DiffAnalyzer._pick_ai_summary_source([schema_rejected(), crashed()]) is None


def test_a_genuine_concern_is_still_reported():
    """The fix must not launder real findings into silence."""
    picked = DiffAnalyzer._pick_ai_summary_source([good()])
    assert picked["concerns"] == ["No test for the zero-size case"]


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


def test_the_record_never_becomes_a_code_scanning_alert():
    """SARIF is code scanning. Every result there is an alert about the SOURCE,
    and an availability record has no file, so it would ship as a security
    finding against uri "" -- the same category error in a different pipe."""
    from src.sarif_exporter import SARIFExporter
    sarif = SARIFExporter().export(_coverage_findings([crashed()]), "o/r", "abc")
    rule_ids = [r.get("ruleId") for r in sarif["runs"][0]["results"]]
    assert "ai-availability" not in rule_ids, rule_ids
    for r in sarif["runs"][0]["results"]:
        for loc in r.get("locations", []):
            uri = loc["physicalLocation"]["artifactLocation"]["uri"]
            assert uri, f"result {r.get('ruleId')} has an empty source location"


def test_a_custom_policy_can_still_choose_to_block_on_it():
    """Scope correction. The claim is that the BUNDLED profiles stay advisory,
    not that no policy can ever escalate this.

    An operator who writes `hard_block_rules: [{severity: low, provable_only:
    true}]` is deliberately asking to block on review loss, and honouring that
    is the system working rather than a defect. Pinned so the narrower claim is
    the one on record.
    """
    from entrypoint import _map_findings
    from src.decision_engine import DecisionEngine
    engine = DecisionEngine("standard")
    engine._policy = {
        "name": "custom",
        "hard_block_rules": [{"severity": "low", "provable_only": True}],
        "condition_rules": [],
        "max_conditions": 2,
    }
    packet = engine.decide(_map_findings(_coverage_findings([crashed()])))
    assert packet.decision == "block"


def test_a_complete_review_records_nothing():
    """No noise on the happy path, or the signal stops meaning anything."""
    assert _find(_coverage_findings([good(), good()]), "ai-availability") is None


def test_partial_loss_is_recorded_too():
    assert _find(_coverage_findings([good(), crashed()]), "ai-availability") is not None


# ---------------------------------------------------------------------------
# 3. Accounting that reconciles
# ---------------------------------------------------------------------------

# test_used_plus_failed_equals_attempted was removed. It computed `used` and
# `failed` with the same predicate it then asserted, so it was a tautology that
# never read either packer's counts. test_analyze_reconciles_its_own_reviewer_counts
# above does the real thing.


def _one_configured_tier_wants_three():
    a = DiffAnalyzer(openrouter_key="x", model_1="openai/m1")
    a._call_provider = lambda p, m, pr: (json.dumps({"codeguard_review": {
        "schema_version": "codeguard.ai_review.v1", "summary": "s",
        "intent": "test", "concerns": [], "risk_assessment": "approve",
        "confidence": 0.9, "rubric_scores": {
            "security_impact": 4, "code_quality": 4, "test_coverage": 4,
            "documentation": 4, "rollback_safety": 4}}}), {"model_id": "m1"})
    return a, DiffAnalyzer._run_multi_model_review(a, "diff", [], "default", 3, True)


def test_the_attempt_reconciles_and_the_tier_ask_survives():
    """Both numbers, because there are two facts.

    An earlier fix made models_requested mean "attempted" so that
    used + failed would reconcile with it. The arithmetic did tidy up, by
    deleting the only record that the tier had asked for three. This asserts
    the reconciliation AND that the ask is still there to be read.
    """
    a, mm = _one_configured_tier_wants_three()
    assert mm["models_attempted"] <= len(a.models)
    assert mm["models_used"] + mm["models_failed"] == mm["models_attempted"]
    assert mm["models_requested"] == 3, "the tier's ask was overwritten by the attempt"


def test_an_under_provisioned_review_is_not_reported_as_complete():
    """The defect this hid: one reviewer configured, three required, and the
    coverage record said complete because nothing it tried had failed."""
    _a, mm = _one_configured_tier_wants_three()
    assert mm["review_coverage"]["complete"] is False, mm["review_coverage"]
    assert mm["review_coverage"]["requested"] == 3


def test_under_provisioning_is_recorded_as_a_finding():
    """Not merely logged. A reviewer that was never configured is exactly as
    absent as one that crashed, and only the crash used to be recorded."""
    classifier = RiskClassifier(rubric="default")
    findings = classifier.classify({
        "files_changed": 1, "lines_added": 1, "lines_removed": 0,
        "files": [], "sensitive_zones": [],
        "review_coverage": {
            "requested": 3, "attempted": 1, "succeeded": 1,
            "failed": 0, "complete": False, "failures": [],
        },
    })["findings"]
    ids = [f.get("id") for f in findings]
    assert "AI-COVERAGE" in ids, ids


def test_no_providers_configured_is_review_loss_not_clean_coverage():
    """The branch that had no coverage record at all.

    With AI enabled but no provider reachable, review_coverage fell back to the
    dataclass default -- attempted 0, complete True -- so a change that wanted
    review and got none was indistinguishable from a clean one.
    """
    cov = DiffAnalyzer._review_coverage([], 2)
    assert cov["complete"] is False, cov
    assert cov["requested"] == 2 and cov["succeeded"] == 0


def test_the_diagnostics_state_how_many_were_requested():
    """Without this the reader subtracts configured minus used and finds a
    reviewer that was never missing."""
    joined = "\n".join(format_review_diagnostics(
        configured=3,
        mmr={"models_used": 2, "models_failed": 0,
             "models_requested": 2, "models_attempted": 2},
    ))
    assert "asked for 2" in joined, joined
    assert "used 2" in joined and "failed 0" in joined, joined


def test_the_diagnostics_say_why_configured_and_requested_differ():
    joined = "\n".join(format_review_diagnostics(
        configured=3, mmr={"models_used": 2, "models_failed": 0, "models_requested": 2},
    ))
    assert "tier" in joined.lower(), joined


def test_the_diagnostics_flag_a_reviewer_that_vanished():
    """attempted > used + failed means a reviewer really did disappear:
    tried for, neither counted as a success nor as a failure."""
    joined = "\n".join(format_review_diagnostics(
        configured=3,
        mmr={"models_used": 1, "models_failed": 0,
             "models_requested": 3, "models_attempted": 3},
    ))
    assert "unaccounted" in joined.lower(), joined


def test_the_diagnostics_flag_an_under_provisioned_tier():
    """The distinct shortfall, and the one that used to be invisible: every
    reviewer we attempted succeeded, and the tier still did not get its review.
    Nothing was 'unaccounted for' -- the reviewers were never there to try."""
    joined = "\n".join(format_review_diagnostics(
        configured=1,
        mmr={"models_used": 1, "models_failed": 0,
             "models_requested": 3, "models_attempted": 1},
    ))
    assert "less than its tier requires" in joined, joined
    assert "unaccounted" not in joined.lower(), joined


# ---------------------------------------------------------------------------
# 4. An outage must not become an all-clear in code scanning
# ---------------------------------------------------------------------------

AVAILABILITY = {
    "id": "AI-COVERAGE", "severity": "low", "rule_id": "ai-availability",
    "message": "AI review coverage: 0 of 2 reviewers required by the risk tier "
               "returned a verdict",
    "file": "", "line": None, "provable": True,
}
REAL_FINDING = {
    "id": "SEC-1", "severity": "high", "rule_id": "hardcoded-secret",
    "message": "Hardcoded credential", "file": "app.py", "line": 3, "provable": True,
}


def test_an_availability_record_is_not_a_policy_finding():
    assert is_policy_finding(AVAILABILITY) is False
    assert is_policy_finding(REAL_FINDING) is True


def test_an_outage_alone_does_not_produce_a_sarif_upload():
    """The regression the filter itself created.

    Filtering inside the exporter left the CALLER's `findings` list truthy, so
    a total outage on an otherwise clean diff produced a SARIF document with
    zero results and executionSuccessful true -- the document that tells code
    scanning every previous alert is resolved. The gate must see the same
    predicate the exporter does.
    """
    assert [f for f in [AVAILABILITY] if is_policy_finding(f)] == []


def test_an_outage_does_not_inflate_the_findings_count():
    """findings_count is documented as policy findings and customers gate on
    it, so an outage flipping it from 0 to 1 changes their merge outcome."""
    counted = [f for f in [AVAILABILITY] if is_policy_finding(f)]
    assert len(counted) == 0
    both = [f for f in [AVAILABILITY, REAL_FINDING] if is_policy_finding(f)]
    assert len(both) == 1


def test_sarif_still_carries_real_findings_alongside_an_outage():
    """The filter must not launder genuine alerts into silence."""
    sarif = SARIFExporter().export([AVAILABILITY, REAL_FINDING], "o/r", "sha")
    rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
    assert rule_ids == ["hardcoded-secret"], rule_ids


# ---------------------------------------------------------------------------
# 5. One predicate, everywhere it decides whether a review counted
# ---------------------------------------------------------------------------

# NOTE: _should_exit_early also carried the narrow predicate and has been
# brought into line, but there is deliberately NO test for it. A mutation test
# showed the two predicates agree on every possible input there -- a rejected
# review always has confidence 0.0, so it can only pull the average below the
# early-exit bar. Any test written for that line would pass with the bug
# present, which is exactly the kind of probe this file exists to stop having.


def test_a_rejected_review_is_not_sealed_as_completed_provenance():
    """Through create_bundle, not through the predicate.

    Asserting review_failed() directly proves only that the predicate works,
    and the predicate was never the bug -- the bug was which filter the sealing
    site used. A parse-rejected review has no "error" key, so the narrow filter
    sealed it as completed review provenance while models_failed counted it as
    failed: the evidence bundle's own numbers contradicted each other, in the
    artifact whose whole claim is that the record says what happened.
    """
    from unittest.mock import MagicMock
    from src.bundle_generator import BundleGenerator

    pr = MagicMock()
    pr.number = 1
    pr.title = "Test PR"
    pr.created_at.isoformat.return_value = "2026-02-08T00:00:00Z"
    pr.user.login = "testuser"
    pr.base.ref = "main"
    pr.head.ref = "feature"

    rejected = dict(schema_rejected(), provider="openrouter", model_name="bad",
                    model_id="bad", prompt_hash="p", response_hash="r")
    usable = dict(good(), provider="openrouter", model_name="ok",
                  model_id="ok", prompt_hash="p2", response_hash="r2")

    bundle = BundleGenerator().create_bundle(
        pr=pr,
        analysis={
            "files_changed": 1, "lines_added": 1, "lines_removed": 0,
            "diff_hash": "sha256:test", "files": [],
            "multi_model_review": {
                "reviews": [rejected, usable],
                "models_used": 1, "models_failed": 1,
            },
        },
        risk_result={"risk_tier": "L1", "findings": [], "requires_approval": False},
        repository="o/r",
        commit_sha="sha",
    )

    # reviews_sealed specifically, not the whole bundle: the raw
    # multi_model_review is snapshotted elsewhere by design, so a substring
    # search over the document would pass no matter what this filter did.
    sealed = None
    for event in bundle.get("events", []):
        payload = event.get("payload") or event.get("data") or {}
        if "reviews_sealed" in payload:
            sealed = payload["reviews_sealed"]
            break
    assert sealed is not None, f"no event carried reviews_sealed: {bundle.keys()}"

    ids = [r.get("model_id") for r in sealed]
    assert "bad" not in ids, f"a rejected review was sealed as provenance: {ids}"
    assert ids == ["ok"], ids


def test_an_incomplete_review_is_not_a_successful_sarif_run():
    """The property that does not depend on the caller getting the gate right.

    executionSuccessful was hardcoded true, so a document with zero results
    read as a completed scan that found nothing -- which is how code scanning
    is told to close prior alerts. If a reviewer did not report, the run did
    not see everything, and must not claim it did.
    """
    outage_only = SARIFExporter().export([AVAILABILITY], "o/r", "sha")
    assert outage_only["runs"][0]["results"] == []
    assert outage_only["runs"][0]["invocations"][0]["executionSuccessful"] is False

    partial = SARIFExporter().export([AVAILABILITY, REAL_FINDING], "o/r", "sha")
    assert partial["runs"][0]["invocations"][0]["executionSuccessful"] is False

    clean = SARIFExporter().export([REAL_FINDING], "o/r", "sha")
    assert clean["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_a_broken_reviewer_is_not_quoted_to_its_peers():
    """The laundering path one round further on.

    A rejected review's fabricated request_changes verdict, and for a rejected
    answer its rejection notice, were rendered into the cross-check prompt as
    an anonymous "Reviewer N". A peer that agreed with it returned the
    malfunction as a genuine finding about the customer's code.
    """
    a = DiffAnalyzer.__new__(DiffAnalyzer)
    prompt = DiffAnalyzer._build_crosscheck_prompt(
        a, "diff", good(), [schema_rejected(), crashed(), good()], 2,
    )
    assert "rejected" not in prompt.lower(), prompt[:400]
    assert prompt.count("### Reviewer") == 1, "a failed reviewer was quoted as a peer"
    assert "No test for the zero-size case" in prompt, "the real peer opinion went missing"
