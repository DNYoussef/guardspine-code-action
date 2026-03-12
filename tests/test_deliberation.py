"""
Tests for multi-round deliberation protocol.

Covers:
  1. Early exit on unanimous high-confidence agreement
  2. Full 2-round deliberation (L2)
  3. Full 3-round deliberation (L3)
  4. Cross-check prompt construction
  5. Output format compatibility with single-pass path
  6. Graceful handling of model errors during deliberation
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from src.analyzer import DiffAnalyzer

SAMPLE_DIFF = (
    "diff --git a/app.py b/app.py\n"
    "index abc1234..def5678 100644\n"
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1,2 +1,4 @@\n"
    " import os\n"
    "+import json\n"
    "+data = json.loads(input())\n"
    " print('hello')\n"
)

# Stub metadata returned alongside model text (simulates API model_id).
_STUB_META = {"model_id": "test-model-v1"}

# A canned review response for mocking.
# Returns (text, metadata) tuple matching the _call_* contract.
def _make_review(verdict="approve", confidence=0.90, concerns=None):
    text = json.dumps({
        "summary": "Test change",
        "intent": "feature",
        "concerns": concerns or [],
        "risk_assessment": verdict,
        "confidence": confidence,
        "rubric_scores": {},
    })
    return text, _STUB_META


def _make_crosscheck_response(verdict="approve", confidence=0.90,
                               concerns=None, changed=False, reason=""):
    text = json.dumps({
        "summary": "Cross-checked",
        "concerns": concerns or [],
        "risk_assessment": verdict,
        "confidence": confidence,
        "verdict_changed": changed,
        "change_reason": reason,
    })
    return text, _STUB_META


class TestDeliberation(unittest.TestCase):
    """Tests for DiffAnalyzer deliberation protocol."""

    def _make_analyzer(self, num_models=2):
        """Create an analyzer with mock providers."""
        analyzer = DiffAnalyzer(openrouter_key="test-key", ai_review=True)
        models = [("openrouter", f"model-{i}") for i in range(num_models)]
        analyzer.models = models
        analyzer.max_models_available = len(models)
        return analyzer

    def test_early_exit_unanimous_high_confidence(self):
        """Round 1 unanimous approve with >= 0.85 confidence should exit early."""
        analyzer = self._make_analyzer(2)
        response = _make_review("approve", 0.95)

        with patch.object(analyzer, "_call_openrouter", return_value=response):
            result = analyzer._run_deliberation(
                SAMPLE_DIFF, [], "default", 2, False)

        self.assertTrue(result["early_exit"])
        self.assertEqual(result["deliberation_rounds"], 1)
        self.assertEqual(result["consensus"]["consensus_risk"], "approve")
        self.assertEqual(result["consensus"]["agreement_score"], 1.0)

    def test_no_early_exit_on_disagreement(self):
        """Disagreement in Round 1 should proceed to Round 2."""
        analyzer = self._make_analyzer(2)
        responses = [
            _make_review("approve", 0.90),
            _make_review("request_changes", 0.80),
        ]
        call_count = [0]

        def mock_call(prompt, model):
            idx = call_count[0]
            call_count[0] += 1
            if idx < 2:
                return responses[idx]
            # Round 2: both agree after cross-check
            return _make_crosscheck_response("approve", 0.90)

        with patch.object(analyzer, "_call_openrouter", side_effect=mock_call):
            result = analyzer._run_deliberation(
                SAMPLE_DIFF, [], "default", 2, False)

        self.assertFalse(result["early_exit"])
        self.assertEqual(result["deliberation_rounds"], 2)

    def test_no_early_exit_low_confidence(self):
        """Unanimous but low confidence should not exit early."""
        analyzer = self._make_analyzer(2)
        r1_response = _make_review("approve", 0.60)
        r2_response = _make_crosscheck_response("approve", 0.70)
        call_count = [0]

        def mock_call(prompt, model):
            idx = call_count[0]
            call_count[0] += 1
            if idx < 2:
                return r1_response
            return r2_response

        with patch.object(analyzer, "_call_openrouter", side_effect=mock_call):
            result = analyzer._run_deliberation(
                SAMPLE_DIFF, [], "default", 2, False)

        self.assertFalse(result["early_exit"])
        self.assertEqual(result["deliberation_rounds"], 2)

    def test_l3_three_rounds(self):
        """L3 with 3 models should run up to 3 rounds."""
        analyzer = self._make_analyzer(3)
        responses = [
            # Round 1: disagreement (no early exit)
            _make_review("approve", 0.90),
            _make_review("comment", 0.70),
            _make_review("approve", 0.85),
            # Round 2
            _make_crosscheck_response("approve", 0.88),
            _make_crosscheck_response("approve", 0.85),
            _make_crosscheck_response("approve", 0.90),
            # Round 3
            _make_crosscheck_response("approve", 0.92),
            _make_crosscheck_response("approve", 0.90),
            _make_crosscheck_response("approve", 0.91),
        ]
        call_count = [0]

        def mock_call(prompt, model):
            idx = call_count[0]
            call_count[0] += 1
            return responses[idx] if idx < len(responses) else responses[-1]

        with patch.object(analyzer, "_call_openrouter", side_effect=mock_call):
            result = analyzer._run_deliberation(
                SAMPLE_DIFF, [], "default", 3, False)

        self.assertEqual(result["deliberation_rounds"], 3)
        self.assertFalse(result["early_exit"])

    def test_output_format_compatible(self):
        """Deliberation output must have same top-level keys as single-pass."""
        analyzer = self._make_analyzer(2)
        response = _make_review("approve", 0.95)

        with patch.object(analyzer, "_call_openrouter", return_value=response):
            result = analyzer._run_deliberation(
                SAMPLE_DIFF, [], "default", 2, False)

        # These keys are required by entrypoint.py and risk_classifier.py
        required_keys = [
            "reviews", "models_used", "models_failed", "models_requested",
            "model_errors", "used_rubric", "rubric_name", "consensus",
        ]
        for key in required_keys:
            self.assertIn(key, result, f"Missing required key: {key}")

        # Extra deliberation keys
        self.assertIn("deliberation_rounds", result)
        self.assertIn("early_exit", result)

    def test_crosscheck_prompt_structure(self):
        """Cross-check prompt should include own review and peer reviews."""
        analyzer = self._make_analyzer(2)
        own = {"risk_assessment": "approve", "confidence": 0.9, "concerns": []}
        peers = [{"risk_assessment": "request_changes", "confidence": 0.8,
                  "concerns": ["SQL injection risk"]}]

        prompt = analyzer._build_crosscheck_prompt(SAMPLE_DIFF, own, peers, 2)

        self.assertIn("Round 1", prompt)
        self.assertIn("approve", prompt)
        self.assertIn("Reviewer 1", prompt)
        self.assertIn("request_changes", prompt)
        self.assertIn("SQL injection risk", prompt)
        self.assertIn("```diff", prompt)

    def test_should_exit_early_logic(self):
        """Unit test _should_exit_early edge cases."""
        analyzer = self._make_analyzer(2)

        # Unanimous + high confidence: exit
        reviews = [
            {"risk_assessment": "approve", "confidence": 0.90},
            {"risk_assessment": "approve", "confidence": 0.92},
        ]
        consensus = {"agreement_score": 1.0, "consensus_risk": "approve"}
        self.assertTrue(analyzer._should_exit_early(reviews, consensus))

        # Unanimous but low confidence: no exit
        reviews_low = [
            {"risk_assessment": "approve", "confidence": 0.60},
            {"risk_assessment": "approve", "confidence": 0.70},
        ]
        self.assertFalse(analyzer._should_exit_early(reviews_low, consensus))

        # Disagreement: no exit
        consensus_disagree = {"agreement_score": 0.5, "consensus_risk": "approve"}
        self.assertFalse(analyzer._should_exit_early(reviews, consensus_disagree))

        # No consensus: no exit
        self.assertFalse(analyzer._should_exit_early(reviews, None))

        # All errors: no exit
        error_reviews = [{"error": "timeout", "confidence": 0}]
        self.assertFalse(analyzer._should_exit_early(
            error_reviews, {"agreement_score": 1.0}))

    def test_model_error_during_crosscheck(self):
        """A model error in Round 2 should not crash the pipeline."""
        analyzer = self._make_analyzer(2)
        call_count = [0]

        def mock_call(prompt, model):
            idx = call_count[0]
            call_count[0] += 1
            if idx < 2:
                # Round 1: disagree to force Round 2
                return _make_review(
                    "approve" if idx == 0 else "request_changes", 0.80)
            if idx == 2:
                raise ConnectionError("API timeout")
            return _make_crosscheck_response("approve", 0.85)

        with patch.object(analyzer, "_call_openrouter", side_effect=mock_call):
            result = analyzer._run_deliberation(
                SAMPLE_DIFF, [], "default", 2, False)

        # Should still produce a result
        self.assertEqual(result["deliberation_rounds"], 2)
        self.assertGreaterEqual(result["models_failed"], 0)
        self.assertIn("consensus", result)

    def test_analyze_deliberate_flag(self):
        """analyze(deliberate=True) should use deliberation for L2+."""
        analyzer = self._make_analyzer(2)
        response = _make_review("approve", 0.95)

        with patch.object(analyzer, "_call_openrouter", return_value=response):
            result = analyzer.analyze(SAMPLE_DIFF, deliberate=True)

        mmr = result.get("multi_model_review", {})
        self.assertIn("deliberation_rounds", mmr)

    def test_analyze_deliberate_false_uses_single_pass(self):
        """analyze(deliberate=False) should use the old single-pass path."""
        analyzer = self._make_analyzer(2)
        response = _make_review("approve", 0.95)

        with patch.object(analyzer, "_call_openrouter", return_value=response):
            result = analyzer.analyze(SAMPLE_DIFF, deliberate=False)

        mmr = result.get("multi_model_review", {})
        self.assertNotIn("deliberation_rounds", mmr)

    def test_dict_concerns_do_not_crash_consensus(self):
        """Models sometimes return concerns as dicts instead of strings."""
        analyzer = self._make_analyzer(2)
        # Simulate model returning structured concern objects
        review_with_dict_concerns = (json.dumps({
            "summary": "Test",
            "intent": "feature",
            "concerns": [
                {"description": "SQL injection risk", "severity": "high"},
                {"message": "Missing input validation"},
                "Plain string concern",
            ],
            "risk_assessment": "request_changes",
            "confidence": 0.85,
            "rubric_scores": {},
        }), _STUB_META)

        with patch.object(analyzer, "_call_openrouter",
                          return_value=review_with_dict_concerns):
            result = analyzer._run_deliberation(
                SAMPLE_DIFF, [], "default", 2, False)

        # Should not crash; concerns should be normalized to strings
        consensus = result["consensus"]
        for c in consensus["combined_concerns"]:
            self.assertIsInstance(c, str)
        self.assertIn("SQL injection risk", consensus["combined_concerns"])


    def test_consensus_strictest_wins_over_majority(self):
        """If 2 approve + 1 request_changes, consensus = request_changes."""
        analyzer = self._make_analyzer(3)
        reviews = [
            {"risk_assessment": "approve", "confidence": 0.90, "concerns": []},
            {"risk_assessment": "approve", "confidence": 0.85, "concerns": []},
            {"risk_assessment": "request_changes", "confidence": 0.80,
             "concerns": ["Missing input validation"]},
        ]
        consensus = analyzer._calculate_consensus(reviews, False)

        self.assertEqual(consensus["consensus_risk"], "request_changes",
                         "Strictest signal should win even when outnumbered")
        self.assertEqual(consensus["models_agreed"], 1)
        self.assertEqual(consensus["total_models"], 3)

    def test_consensus_unanimous_approve_stays_approve(self):
        """If all models approve, consensus = approve (unchanged)."""
        analyzer = self._make_analyzer(3)
        reviews = [
            {"risk_assessment": "approve", "confidence": 0.90, "concerns": []},
            {"risk_assessment": "approve", "confidence": 0.85, "concerns": []},
            {"risk_assessment": "approve", "confidence": 0.92, "concerns": []},
        ]
        consensus = analyzer._calculate_consensus(reviews, False)

        self.assertEqual(consensus["consensus_risk"], "approve")
        self.assertEqual(consensus["agreement_score"], 1.0)

    def test_consensus_comment_beats_approve(self):
        """If 2 approve + 1 comment, consensus = comment (stricter)."""
        analyzer = self._make_analyzer(3)
        reviews = [
            {"risk_assessment": "approve", "confidence": 0.90, "concerns": []},
            {"risk_assessment": "approve", "confidence": 0.85, "concerns": []},
            {"risk_assessment": "comment", "confidence": 0.70,
             "concerns": ["Unusual pattern"]},
        ]
        consensus = analyzer._calculate_consensus(reviews, False)

        self.assertEqual(consensus["consensus_risk"], "comment",
                         "Comment should beat approve (stricter signal)")


if __name__ == "__main__":
    unittest.main()
