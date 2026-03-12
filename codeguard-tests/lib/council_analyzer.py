"""
Council analyzer: scoring rubric for AI council quality metrics.

Computes four sub-metrics for L2+ cases:
1. Naive core-issue hit rate
2. Round-robin delta
3. Consensus correctness
4. Actionability score
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from test_cases.ground_truth import TestCase


@dataclass
class CouncilScore:
    """Scores for a single L2+ test case council evaluation."""
    case_id: str
    naive_hit_rate: float          # % of models whose naive output hit >= 1 expected signal/category
    round_robin_deltas: Dict[str, int]  # per model: +N/-N/0 signal coverage change
    consensus_correct: bool        # does consensus pass classification rules?
    actionability_pct: float       # % of findings with both remediation AND file path
    details: Dict[str, Any] = field(default_factory=dict)


def _signal_overlap(model_signals: List[str], expected_signals: List[str],
                    expected_categories: List[str]) -> int:
    """Count how many expected signals or categories appear in model output."""
    expected = set(s.lower() for s in expected_signals + expected_categories)
    actual = set(s.lower() for s in model_signals)
    return len(expected & actual)


def analyze_council(case: TestCase, council: Dict[str, Any],
                    top_level_findings: List[Dict[str, Any]] = None) -> CouncilScore:
    """
    Score council quality for a single L2+ test case.

    Args:
        case: TestCase with expected signals/categories.
        council: Council output dict from ParsedResult.

    Returns:
        CouncilScore with all four metrics.
    """
    naive = council.get("naive", {})
    round_robin = council.get("round_robin", {})
    consensus = council.get("consensus", {})
    models = council.get("models", [])

    # 1. Naive core-issue hit rate
    hits = 0
    total_models = len(naive)
    for model_name, model_data in naive.items():
        model_signals = model_data.get("signals", [])
        model_findings = model_data.get("findings", [])
        if _signal_overlap(model_signals, case.expected_signals, case.expected_categories) > 0:
            hits += 1
    naive_hit_rate = hits / total_models if total_models > 0 else 0.0

    # 2. Round-robin delta (per model)
    round_robin_deltas = {}
    for model_name in models:
        naive_data = naive.get(model_name, {})
        rr_data = round_robin.get(model_name, {})

        naive_signals = set(s.lower() for s in naive_data.get("signals", []))
        # After round-robin, the model may have accepted/added findings
        accepted = set(rr_data.get("accepted", []))
        added = set(rr_data.get("added", []))
        rejected = set(rr_data.get("rejected", []))

        # Delta = (accepted + added) - rejected relative to naive
        naive_coverage = _signal_overlap(
            list(naive_signals), case.expected_signals, case.expected_categories
        )
        # Post-RR: assume accepted findings contribute, added findings contribute
        post_rr_signals = naive_signals.copy()
        # We approximate: if round-robin risk_level increased, that's a positive delta
        rr_risk = rr_data.get("risk_level", naive_data.get("risk_level", 0))
        naive_risk = naive_data.get("risk_level", 0)

        delta = 0
        if rr_risk > naive_risk:
            delta = rr_risk - naive_risk
        elif rr_risk < naive_risk:
            delta = rr_risk - naive_risk
        else:
            delta = len(added) - len(rejected)

        round_robin_deltas[model_name] = delta

    # 3. Consensus correctness
    consensus_risk = consensus.get("risk_level", 0)
    expected = case.expected_risk_level

    if expected == 4:
        # L4 requires strict match only
        consensus_correct = consensus_risk == expected
    else:
        # L2-L3: tolerant match (abs diff <= 1)
        consensus_correct = abs(consensus_risk - expected) <= 1

    # 4. Actionability score
    consensus_findings = council.get("consensus", {}).get("findings", [])

    # Resolve finding IDs against top-level findings
    all_findings = []
    if isinstance(consensus_findings, list) and consensus_findings:
        if isinstance(consensus_findings[0], dict):
            # Already full finding objects
            all_findings = consensus_findings
        elif top_level_findings:
            # IDs -- resolve against top-level findings list
            finding_map = {f.get("id"): f for f in top_level_findings if isinstance(f, dict)}
            for fid in consensus_findings:
                if fid in finding_map:
                    all_findings.append(finding_map[fid])

    actionable = 0
    total_findings = len(all_findings)
    for finding in all_findings:
        has_remediation = bool(finding.get("remediation"))
        has_file_path = bool(finding.get("file_paths") or finding.get("file_path"))
        if has_remediation and has_file_path:
            actionable += 1

    actionability_pct = actionable / total_findings if total_findings > 0 else 0.0

    return CouncilScore(
        case_id=case.id,
        naive_hit_rate=naive_hit_rate,
        round_robin_deltas=round_robin_deltas,
        consensus_correct=consensus_correct,
        actionability_pct=actionability_pct,
        details={
            "naive_hits": hits,
            "naive_total": total_models,
            "consensus_risk_level": consensus_risk,
            "expected_risk_level": expected,
            "total_findings": total_findings,
            "actionable_findings": actionable,
        },
    )


def compute_actionability_from_findings(findings: List[Dict[str, Any]]) -> float:
    """
    Compute actionability percentage from a list of finding dicts.

    A finding is actionable if it has BOTH:
    - A concrete remediation step
    - A file path reference
    """
    if not findings:
        return 0.0

    actionable = 0
    for f in findings:
        has_remediation = bool(f.get("remediation"))
        has_file = bool(f.get("file_paths") or f.get("file_path"))
        if has_remediation and has_file:
            actionable += 1

    return actionable / len(findings)
