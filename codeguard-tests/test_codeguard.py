"""
CodeGuard validation test suite.

Four test functions:
1. test_detection       -- Did CodeGuard detect the issue?
2. test_classification  -- Risk level: strict + tolerant match
3. test_council_consensus -- L2+: council quality metrics
4. test_controls_do_not_overflag -- L0/L1 controls
"""
from __future__ import annotations

import pytest

from test_cases.known_incidents import KNOWN_INCIDENTS
from test_cases.ground_truth import TestCase
from lib.codeguard_runner import ParsedResult
from lib.council_analyzer import analyze_council, compute_actionability_from_findings


def _is_detected(result: ParsedResult, case: TestCase) -> bool:
    """
    A case is "detected" if ANY of the following are true:
    - detected == true in output
    - risk_level >= 1 in output
    - Any expected signal appears in signals[] or finding summaries/evidence
    """
    if result.detected:
        return True
    if result.risk_level >= 1:
        return True

    # Check signals
    result_signals_lower = set(s.lower() for s in result.signals)
    for sig in case.expected_signals:
        if sig.lower() in result_signals_lower:
            return True

    # Check finding summaries and evidence
    for finding in result.findings:
        summary = finding.get("summary", "").lower()
        evidence_list = finding.get("evidence", [])
        for sig in case.expected_signals:
            sig_lower = sig.lower()
            if sig_lower in summary:
                return True
            for ev in evidence_list:
                if sig_lower in ev.lower():
                    return True

    return False


# ---------------------------------------------------------------------------
# Test 1: Detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", KNOWN_INCIDENTS, ids=lambda c: c.id)
def test_detection(case: TestCase, codeguard_runner):
    """Did CodeGuard detect the issue? (L0 controls: should NOT detect)"""
    result = codeguard_runner.run(case)
    detected = _is_detected(result, case)

    # For L0, expected detection is False
    if case.expected_risk_level == 0:
        expected_detected = False
    else:
        expected_detected = True

    # Record for report
    codeguard_runner.record_result({
        "case_id": case.id,
        "expected_level": case.expected_risk_level,
        "actual_level": result.risk_level,
        "detected": detected,
        "expected_detected": expected_detected,
        "strict_match": result.risk_level == case.expected_risk_level,
        "tolerant_match": abs(result.risk_level - case.expected_risk_level) <= 1,
        "pass_detection": detected == expected_detected,
        "pass_classification": (
            result.risk_level == case.expected_risk_level
            if case.expected_risk_level == 4
            else abs(result.risk_level - case.expected_risk_level) <= 1
        ),
    })

    if case.expected_risk_level == 0:
        assert not detected, (
            f"{case.id}: L0 control should NOT be detected, but was. "
            f"Signals: {result.signals}"
        )
    else:
        assert detected, (
            f"{case.id}: Expected detection for L{case.expected_risk_level} case, "
            f"but not detected. risk_level={result.risk_level}, "
            f"signals={result.signals}"
        )


# ---------------------------------------------------------------------------
# Test 2: Classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", KNOWN_INCIDENTS, ids=lambda c: c.id)
def test_classification(case: TestCase, codeguard_runner):
    """Risk level: strict match + tolerant match. L4 requires strict."""
    result = codeguard_runner.run(case)

    strict = result.risk_level == case.expected_risk_level
    tolerant = abs(result.risk_level - case.expected_risk_level) <= 1

    if case.expected_risk_level == 4:
        # L4: strict only, no tolerance
        assert strict, (
            f"{case.id}: L4 case MUST be classified as L4 (strict). "
            f"Got L{result.risk_level}. "
            f"A supply-chain backdoor classified as L3 is a test failure."
        )
    else:
        assert tolerant, (
            f"{case.id}: Expected L{case.expected_risk_level} (+/-1 tolerance). "
            f"Got L{result.risk_level}."
        )


# ---------------------------------------------------------------------------
# Test 3: Council consensus (L2+ only)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "case",
    [c for c in KNOWN_INCIDENTS if c.expected_risk_level >= 2],
    ids=lambda c: c.id,
)
def test_council_consensus(case: TestCase, codeguard_runner):
    """For L2+: naive hit rate, round-robin delta, consensus correctness, actionability."""
    result = codeguard_runner.run(case)
    council = result.council

    # Skip if council not enabled (shouldn't happen for L2+)
    if not council.get("enabled", False):
        pytest.skip(f"{case.id}: Council not enabled for L{case.expected_risk_level}")

    score = analyze_council(case, council, top_level_findings=result.findings)
    codeguard_runner.record_council_score(score)

    # Naive hit rate: at least one model should catch the core issue
    assert score.naive_hit_rate > 0, (
        f"{case.id}: No model caught any expected signal in naive phase. "
        f"Expected signals: {case.expected_signals}"
    )

    # Consensus correctness
    assert score.consensus_correct, (
        f"{case.id}: Council consensus risk_level "
        f"{score.details['consensus_risk_level']} doesn't match expected "
        f"L{case.expected_risk_level} "
        f"(strict for L4, +/-1 for L2-L3)"
    )

    # Actionability: check top-level findings (not just consensus finding IDs)
    actionability = compute_actionability_from_findings(result.findings)
    if result.findings:
        assert actionability > 0, (
            f"{case.id}: No findings have both remediation and file path. "
            f"Total findings: {len(result.findings)}"
        )


# ---------------------------------------------------------------------------
# Test 4: Controls don't overflag (L0/L1 only)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "case",
    [c for c in KNOWN_INCIDENTS if c.expected_risk_level <= 1],
    ids=lambda c: c.id,
)
def test_controls_do_not_overflag(case: TestCase, codeguard_runner):
    """L0 must not detect. L1 must not classify as L2+."""
    result = codeguard_runner.run(case)

    if case.expected_risk_level == 0:
        detected = _is_detected(result, case)
        assert not detected, (
            f"{case.id}: L0 control was falsely detected. "
            f"risk_level={result.risk_level}, signals={result.signals}"
        )
    else:
        # L1: must not classify as L2+
        assert result.risk_level <= 1, (
            f"{case.id}: L1 case over-classified as L{result.risk_level}. "
            f"Should be L0 or L1."
        )
