"""Tests for lean black-box confidence calibration."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from src.bundle_generator import BundleGenerator
from src.confidence_calibrator import (
    _compute_metrics,
    annotate_analysis_with_calibration,
    build_artifact,
    load_artifact,
    make_consensus_training_row,
    make_review_training_row,
    save_artifact,
)


def _make_analysis(
    consensus_risk: str,
    tier: str,
    expected_conf: float,
    *,
    agreement: float,
    expected_flag: bool,
) -> tuple[dict, bool]:
    provider = "openrouter"
    model_name = "anthropic/claude-sonnet-4.5"
    review_a = {
        "provider": provider,
        "model_name": model_name,
        "model_id": model_name,
        "risk_assessment": consensus_risk,
        "confidence": expected_conf,
        "concerns": ["user input reaches SQL"] if expected_flag else [],
    }
    review_b = {
        "provider": provider,
        "model_name": "openai/gpt-5.2",
        "model_id": "openai/gpt-5.2",
        "risk_assessment": consensus_risk,
        "confidence": max(0.05, expected_conf - 0.05),
        "concerns": ["validation removed"] if expected_flag else [],
    }
    analysis = {
        "files_changed": 2 if expected_flag else 1,
        "lines_added": 24 if expected_flag else 8,
        "lines_removed": 3 if expected_flag else 1,
        "sensitive_zones": [{"zone": "auth", "file": "app.py", "line": 10}] if expected_flag else [],
        "preliminary_tier": tier,
        "models_used": 2,
        "models_failed": 0,
        "consensus_risk": consensus_risk,
        "agreement_score": agreement,
        "multi_model_review": {
            "reviews": [review_a, review_b],
            "consensus": {
                "consensus_risk": consensus_risk,
                "agreement_score": agreement,
                "combined_concerns": ["validation removed"] if expected_flag else [],
            },
            "deliberation_rounds": 2,
            "early_exit": False,
        },
    }
    return analysis, expected_flag


class TestConfidenceCalibrator(unittest.TestCase):
    def _training_rows(self) -> list[dict]:
        rows = []
        for analysis, expected_flag in [
            _make_analysis("request_changes", "L3", 0.93, agreement=1.0, expected_flag=True),
            _make_analysis("comment", "L3", 0.62, agreement=0.5, expected_flag=True),
            _make_analysis("approve", "L1", 0.88, agreement=1.0, expected_flag=False),
            _make_analysis("approve", "L2", 0.40, agreement=0.5, expected_flag=True),
            _make_analysis("request_changes", "L4", 0.35, agreement=1.0, expected_flag=False),
        ]:
            metadata = {
                "sample": f"{analysis['consensus_risk']}-{analysis['preliminary_tier']}",
                "dataset": "unit",
                "category": "vulnerable" if expected_flag else "clean",
                "tier_preliminary": analysis["preliminary_tier"],
                "tier_final": analysis["preliminary_tier"],
            }
            rows.append(make_consensus_training_row(analysis, expected_flag, metadata))
            for review in analysis["multi_model_review"]["reviews"]:
                rows.append(make_review_training_row(review, analysis, expected_flag, metadata))
        return rows

    def test_build_artifact_round_trip_and_annotate(self):
        rows = self._training_rows()
        artifact = build_artifact(rows, source="unit-test", epochs=400, learning_rate=0.25, l2=0.01)
        self.assertIn("review", artifact["models"])
        self.assertIn("consensus", artifact["models"])

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibrator.json"
            save_artifact(artifact, path)
            loaded = load_artifact(path)

        analysis, _ = _make_analysis("request_changes", "L3", 0.91, agreement=1.0, expected_flag=True)
        summary = annotate_analysis_with_calibration(analysis, loaded)

        self.assertEqual(summary["source"], "black_box_calibrator_v1")
        self.assertIsNotNone(summary["calibrated_verdict_p_correct"])
        self.assertGreaterEqual(summary["calibrated_verdict_p_correct"], 0.0)
        self.assertLessEqual(summary["calibrated_verdict_p_correct"], 1.0)
        self.assertEqual(summary["reviews_calibrated"], 2)

        for review in analysis["multi_model_review"]["reviews"]:
            self.assertIn("confidence_self_reported", review)
            self.assertIn("calibrated_confidence", review)
            self.assertEqual(review["confidence_source"], "black_box_calibrator_v1")

    def test_bundle_snapshot_carries_confidence_calibration(self):
        pr = MagicMock()
        pr.number = 7
        pr.title = "Calibrated review"
        pr.created_at = MagicMock()
        pr.created_at.isoformat.return_value = "2026-03-19T00:00:00Z"
        pr.user = MagicMock()
        pr.user.login = "tester"
        pr.base = MagicMock()
        pr.base.ref = "main"
        pr.head = MagicMock()
        pr.head.ref = "feature/calibration"

        analysis, _ = _make_analysis("comment", "L3", 0.71, agreement=0.5, expected_flag=True)
        analysis["confidence_calibration"] = {
            "enabled": True,
            "source": "black_box_calibrator_v1",
            "calibrated_verdict_p_correct": 0.6421,
        }
        analysis["multi_model_review"]["reviews"][0]["calibrated_confidence"] = 0.6123

        bundle = BundleGenerator().create_bundle(
            pr=pr,
            analysis=analysis,
            risk_result={
                "risk_tier": "L3",
                "risk_drivers": [],
                "findings": [],
                "rationale": "Needs reviewer attention",
                "scores": {},
            },
            repository="guardspine/mono",
            commit_sha="abc1234",
        )

        self.assertEqual(
            bundle["analysis_snapshot"]["confidence_calibration"]["source"],
            "black_box_calibrator_v1",
        )
        self.assertAlmostEqual(
            bundle["analysis_snapshot"]["confidence_calibration"]["calibrated_verdict_p_correct"],
            0.6421,
        )
        event = next(e for e in bundle["events"] if e["event_type"] == "analysis_completed")
        self.assertEqual(
            event["data"]["confidence_calibration"]["source"],
            "black_box_calibrator_v1",
        )

    def test_ece_uses_empirical_correctness_rate(self):
        metrics = _compute_metrics(
            labels=[1, 1, 0, 0],
            probabilities=[0.9, 0.8, 0.2, 0.1],
            bins=5,
        )

        self.assertAlmostEqual(metrics["accuracy"], 1.0)
        self.assertAlmostEqual(metrics["brier"], 0.025)
        self.assertAlmostEqual(metrics["ece"], 0.15)


if __name__ == "__main__":
    unittest.main()
