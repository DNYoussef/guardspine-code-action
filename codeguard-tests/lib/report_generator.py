"""
Report generator: produces summary.md and summary.json from test results.

Emits:
- Per-case pass/fail table
- Confusion matrix (5x5)
- False negative rate (headline metric)
- False positive rate
- Council effectiveness metrics
- Per-model breakdown
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from lib.council_analyzer import CouncilScore

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def _level_label(level: int) -> str:
    return f"L{level}"


def generate_reports(
    results: List[Dict[str, Any]],
    council_scores: List[CouncilScore],
) -> None:
    """
    Generate summary.md and summary.json from test results.

    Args:
        results: List of dicts with keys:
            case_id, expected_level, actual_level, detected, expected_detected,
            strict_match, tolerant_match, pass_detection, pass_classification
        council_scores: List of CouncilScore for L2+ cases.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    report_data = _build_report_data(results, council_scores)

    # Write JSON
    json_path = REPORTS_DIR / "summary.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)

    # Write Markdown
    md_path = REPORTS_DIR / "summary.md"
    md_content = _render_markdown(report_data)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)


def _build_report_data(
    results: List[Dict[str, Any]],
    council_scores: List[CouncilScore],
) -> Dict[str, Any]:
    """Build the full report data structure."""
    # Per-case table
    case_table = []
    for r in results:
        case_table.append({
            "case_id": r["case_id"],
            "expected_level": r["expected_level"],
            "actual_level": r["actual_level"],
            "detected": r["detected"],
            "expected_detected": r["expected_detected"],
            "strict_match": r["strict_match"],
            "tolerant_match": r["tolerant_match"],
            "pass_detection": r["pass_detection"],
            "pass_classification": r["pass_classification"],
        })

    # Confusion matrix (5x5)
    matrix = [[0] * 5 for _ in range(5)]
    for r in results:
        expected = r["expected_level"]
        actual = r["actual_level"]
        if 0 <= expected <= 4 and 0 <= actual <= 4:
            matrix[expected][actual] += 1

    # False negative rate: undetected L2-L4 / total L2-L4
    l2_plus = [r for r in results if r["expected_level"] >= 2]
    l2_plus_missed = [r for r in l2_plus if not r["detected"]]
    fn_rate = len(l2_plus_missed) / len(l2_plus) if l2_plus else 0.0

    # False positive rate: detected L0 / total L0
    l0_cases = [r for r in results if r["expected_level"] == 0]
    l0_detected = [r for r in l0_cases if r["detected"]]
    fp_rate = len(l0_detected) / len(l0_cases) if l0_cases else 0.0

    # Council scores
    council_data = []
    for cs in council_scores:
        council_data.append({
            "case_id": cs.case_id,
            "naive_hit_rate": cs.naive_hit_rate,
            "round_robin_deltas": cs.round_robin_deltas,
            "consensus_correct": cs.consensus_correct,
            "actionability_pct": cs.actionability_pct,
            "details": cs.details,
        })

    avg_naive_hit = (
        sum(cs.naive_hit_rate for cs in council_scores) / len(council_scores)
        if council_scores else 0.0
    )
    avg_actionability = (
        sum(cs.actionability_pct for cs in council_scores) / len(council_scores)
        if council_scores else 0.0
    )
    consensus_correct_count = sum(1 for cs in council_scores if cs.consensus_correct)
    consensus_correct_rate = (
        consensus_correct_count / len(council_scores)
        if council_scores else 0.0
    )

    # Per-model breakdown
    model_stats: Dict[str, Dict[str, int]] = {}
    for cs in council_scores:
        for model_name, delta in cs.round_robin_deltas.items():
            if model_name not in model_stats:
                model_stats[model_name] = {"cases": 0, "positive_deltas": 0, "negative_deltas": 0, "neutral": 0}
            model_stats[model_name]["cases"] += 1
            if delta > 0:
                model_stats[model_name]["positive_deltas"] += 1
            elif delta < 0:
                model_stats[model_name]["negative_deltas"] += 1
            else:
                model_stats[model_name]["neutral"] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_cases": len(results),
        "case_table": case_table,
        "confusion_matrix": matrix,
        "false_negative_rate": fn_rate,
        "false_positive_rate": fp_rate,
        "council_effectiveness": {
            "avg_naive_hit_rate": avg_naive_hit,
            "consensus_correct_rate": consensus_correct_rate,
            "avg_actionability_pct": avg_actionability,
            "per_case": council_data,
        },
        "per_model_breakdown": model_stats,
    }


def _render_markdown(data: Dict[str, Any]) -> str:
    """Render the report data as Markdown."""
    lines = []
    lines.append("# CodeGuard Validation Report")
    lines.append("")
    lines.append(f"Generated: {data['generated_at']}")
    lines.append(f"Total cases: {data['total_cases']}")
    lines.append("")

    # Headline metrics
    lines.append("## Headline Metrics")
    lines.append("")
    fn_pct = data["false_negative_rate"] * 100
    fp_pct = data["false_positive_rate"] * 100
    lines.append(f"- **False Negative Rate (L2-L4):** {fn_pct:.1f}%")
    lines.append(f"- **False Positive Rate (L0):** {fp_pct:.1f}%")
    lines.append("")

    # Per-case table
    lines.append("## Per-Case Results")
    lines.append("")
    lines.append("| Case | Expected | Actual | Detected | Strict | Tolerant | Pass |")
    lines.append("|------|----------|--------|----------|--------|----------|------|")
    for c in data["case_table"]:
        det = "Y" if c["detected"] else "N"
        strict = "Y" if c["strict_match"] else "N"
        tolerant = "Y" if c["tolerant_match"] else "N"
        passed = "PASS" if c["pass_classification"] else "FAIL"
        lines.append(
            f"| {c['case_id']} | L{c['expected_level']} | L{c['actual_level']} "
            f"| {det} | {strict} | {tolerant} | {passed} |"
        )
    lines.append("")

    # Confusion matrix
    lines.append("## Confusion Matrix (Expected x Actual)")
    lines.append("")
    lines.append("|  | L0 | L1 | L2 | L3 | L4 |")
    lines.append("|--|----|----|----|----|-----|")
    matrix = data["confusion_matrix"]
    for i in range(5):
        row = " | ".join(str(matrix[i][j]) for j in range(5))
        lines.append(f"| **L{i}** | {row} |")
    lines.append("")

    # Council effectiveness
    ce = data["council_effectiveness"]
    lines.append("## Council Effectiveness (L2+ only)")
    lines.append("")
    lines.append(f"- **Avg Naive Hit Rate:** {ce['avg_naive_hit_rate'] * 100:.1f}%")
    lines.append(f"- **Consensus Correct Rate:** {ce['consensus_correct_rate'] * 100:.1f}%")
    lines.append(f"- **Avg Actionability:** {ce['avg_actionability_pct'] * 100:.1f}%")
    lines.append("")

    # Round-robin delta summary
    lines.append("### Round-Robin Delta by Case")
    lines.append("")
    for pc in ce["per_case"]:
        deltas = ", ".join(
            f"{m}: {'+' if d > 0 else ''}{d}"
            for m, d in pc["round_robin_deltas"].items()
        )
        lines.append(f"- **{pc['case_id']}:** {deltas}")
    lines.append("")

    # Per-model breakdown
    if data["per_model_breakdown"]:
        lines.append("## Per-Model Breakdown")
        lines.append("")
        lines.append("| Model | Cases | +Delta | -Delta | Neutral |")
        lines.append("|-------|-------|--------|--------|---------|")
        for model, stats in data["per_model_breakdown"].items():
            lines.append(
                f"| {model} | {stats['cases']} | {stats['positive_deltas']} "
                f"| {stats['negative_deltas']} | {stats['neutral']} |"
            )
        lines.append("")

    return "\n".join(lines)
