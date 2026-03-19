"""Integration test for entrypoint confidence calibrator plumbing."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from entrypoint import main
from src.confidence_calibrator import (
    build_artifact,
    make_consensus_training_row,
    make_review_training_row,
    save_artifact,
)


def _make_analysis(consensus_risk: str, confidence: float, agreement: float) -> dict:
    reviews = [
        {
            "provider": "openrouter",
            "model_name": "anthropic/claude-sonnet-4.5",
            "model_id": "anthropic/claude-sonnet-4.5",
            "risk_assessment": consensus_risk,
            "confidence": confidence,
            "concerns": ["validation removed"] if consensus_risk != "approve" else [],
        },
        {
            "provider": "openrouter",
            "model_name": "openai/gpt-5.2",
            "model_id": "openai/gpt-5.2",
            "risk_assessment": consensus_risk,
            "confidence": max(0.05, confidence - 0.08),
            "concerns": ["user input reaches sink"] if consensus_risk != "approve" else [],
        },
    ]
    return {
        "files_changed": 1,
        "lines_added": 14,
        "lines_removed": 2,
        "files": [],
        "sensitive_zones": [{"zone": "database", "file": "app.py", "line": 9}],
        "diff_hash": "sha256:diff",
        "preliminary_tier": "L3",
        "models_used": 2,
        "models_failed": 0,
        "model_errors": [],
        "consensus_risk": consensus_risk,
        "agreement_score": agreement,
        "multi_model_review": {
            "reviews": reviews,
            "consensus": {
                "consensus_risk": consensus_risk,
                "agreement_score": agreement,
                "combined_concerns": ["validation removed"] if consensus_risk != "approve" else [],
            },
            "deliberation_rounds": 1,
            "early_exit": False,
        },
    }


def _write_calibrator(path: Path) -> None:
    rows: list[dict] = []
    training_examples = [
        (_make_analysis("request_changes", 0.94, 1.0), True, "vulnerable"),
        (_make_analysis("comment", 0.68, 0.5), True, "introducing"),
        (_make_analysis("approve", 0.89, 1.0), False, "clean"),
        (_make_analysis("approve", 0.31, 0.5), True, "vulnerable"),
    ]
    for idx, (analysis, expected_flag, category) in enumerate(training_examples, start=1):
        metadata = {
            "sample": f"sample-{idx}.patch",
            "dataset": "unit",
            "category": category,
            "tier_preliminary": analysis["preliminary_tier"],
            "tier_final": analysis["preliminary_tier"],
        }
        rows.append(make_consensus_training_row(analysis, expected_flag, metadata))
        for review in analysis["multi_model_review"]["reviews"]:
            rows.append(make_review_training_row(review, analysis, expected_flag, metadata))

    artifact = build_artifact(rows, source="unit-test", epochs=300, learning_rate=0.2, l2=0.01)
    save_artifact(artifact, path)


class TestEntrypointConfidenceCalibrator(unittest.TestCase):
    def test_main_emits_calibrated_confidence_outputs(self):
        raw_diff = (
            "diff --git a/app.py b/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,0 +1,2 @@\n"
            "+query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
            "+return db.execute(query)\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            event_path = workspace / "event.json"
            calibrator_path = workspace / ".guardspine" / "calibration" / "codeguard-confidence-v1.json"
            calibrator_path.parent.mkdir(parents=True, exist_ok=True)
            event_path.write_text(json.dumps({"pull_request": {"number": 11}}), encoding="utf-8")
            _write_calibrator(calibrator_path)

            pr = MagicMock()
            pr.number = 11
            pr.title = "Risky query"
            pr.state = "open"
            pr.mergeable = True

            repo = MagicMock()
            repo.get_pull.return_value = pr

            gh = MagicMock()
            gh.get_repo.return_value = repo

            class StubAnalyzer:
                def __init__(self, *args, **kwargs):
                    pass

                def analyze(
                    self,
                    diff_content,
                    rubric="default",
                    tier_override=None,
                    deliberate=False,
                    ai_diff_content=None,
                ):
                    self.last_diff = diff_content
                    return _make_analysis("request_changes", 0.91, 1.0)

            class StubClassifier:
                @staticmethod
                def discover_builtin_rubrics(_repo_root):
                    return {}

                @staticmethod
                def builtin_names(_repo_root):
                    return {"default"}

                def __init__(self, *args, **kwargs):
                    pass

                def classify(self, analysis):
                    return {
                        "risk_tier": "L3",
                        "risk_drivers": ["database write in sensitive path"],
                        "findings": [],
                        "scores": {},
                        "rationale": "Needs human review",
                    }

            packet = MagicMock()
            packet.decision = "merge-with-conditions"
            packet.hard_blocks = []
            packet.conditions = []
            packet.advisory = []

            outputs: dict[str, str] = {}

            with patch.dict(
                os.environ,
                {
                    "GITHUB_WORKSPACE": str(workspace),
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_REPOSITORY": "guardspine/mono",
                    "GITHUB_SHA": "abc1234",
                    "GITHUB_REF": "refs/pull/11/head",
                    "INPUT_GITHUB_TOKEN": "token",
                    "INPUT_POST_COMMENT": "false",
                    "INPUT_GENERATE_BUNDLE": "false",
                    "INPUT_UPLOAD_SARIF": "false",
                    "INPUT_AI_REVIEW": "false",
                    "INPUT_AUTO_MERGE": "false",
                    "INPUT_CONFIDENCE_CALIBRATOR": ".guardspine/calibration/codeguard-confidence-v1.json",
                },
                clear=False,
            ):
                with patch("entrypoint.Github", return_value=gh):
                    with patch("entrypoint.fetch_pr_diff", return_value=raw_diff):
                        with patch("entrypoint.DiffAnalyzer", StubAnalyzer):
                            with patch("entrypoint.RiskClassifier", StubClassifier):
                                with patch("entrypoint.DecisionEngine") as mock_engine:
                                    with patch("entrypoint.render_decision_card", return_value="card"):
                                        with patch("entrypoint.set_output", side_effect=lambda k, v: outputs.__setitem__(k, v)):
                                            mock_engine.return_value.decide.return_value = packet
                                            with self.assertRaises(SystemExit) as exit_ctx:
                                                main()

            self.assertEqual(exit_ctx.exception.code, 0)
            self.assertEqual(outputs["confidence_source"], "black_box_calibrator_v1")
            self.assertIn("calibrated_confidence", outputs)
            calibrated = float(outputs["calibrated_confidence"])
            self.assertGreaterEqual(calibrated, 0.0)
            self.assertLessEqual(calibrated, 1.0)
            self.assertEqual(outputs["consensus_risk"], "request_changes")


if __name__ == "__main__":
    unittest.main()
