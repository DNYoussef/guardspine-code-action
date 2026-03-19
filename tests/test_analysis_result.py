"""Tests for AnalysisResult dataclass dict-compatibility."""

import unittest
from src.analyzer import AnalysisResult


class TestAnalysisResultDefaults(unittest.TestCase):
    """AnalysisResult initializes with sane defaults."""

    def test_default_construction(self):
        r = AnalysisResult()
        self.assertEqual(r.files_changed, 0)
        self.assertEqual(r.lines_added, 0)
        self.assertEqual(r.lines_removed, 0)
        self.assertEqual(r.files, [])
        self.assertEqual(r.sensitive_zones, [])
        self.assertEqual(r.diff_hash, "")
        self.assertEqual(r.preliminary_tier, "L2")
        self.assertFalse(r.parse_error)
        self.assertEqual(r.models_used, 0)
        self.assertEqual(r.consensus_risk, "")
        self.assertEqual(r.agreement_score, 0.0)
        self.assertEqual(r.confidence_calibration, {})
        self.assertEqual(r.pii_shield, {"enabled": False})
        self.assertIsNone(r.sanitization)

    def test_keyword_construction(self):
        r = AnalysisResult(files_changed=5, lines_added=100, diff_hash="sha256:abc")
        self.assertEqual(r.files_changed, 5)
        self.assertEqual(r.lines_added, 100)
        self.assertEqual(r.diff_hash, "sha256:abc")


class TestAnalysisResultDictCompat(unittest.TestCase):
    """AnalysisResult supports dict-style access for backward compatibility."""

    def setUp(self):
        self.result = AnalysisResult(
            files_changed=3,
            lines_added=42,
            lines_removed=10,
            diff_hash="sha256:deadbeef",
        )

    def test_getitem(self):
        self.assertEqual(self.result["files_changed"], 3)
        self.assertEqual(self.result["diff_hash"], "sha256:deadbeef")

    def test_getitem_missing_raises_keyerror(self):
        with self.assertRaises(KeyError):
            _ = self.result["nonexistent_key"]

    def test_setitem(self):
        self.result["raw_diff_hash"] = "sha256:cafe"
        self.assertEqual(self.result.raw_diff_hash, "sha256:cafe")
        self.assertEqual(self.result["raw_diff_hash"], "sha256:cafe")

    def test_contains(self):
        self.assertIn("files_changed", self.result)
        self.assertIn("diff_hash", self.result)
        self.assertNotIn("nonexistent", self.result)

    def test_get_with_default(self):
        self.assertEqual(self.result.get("files_changed"), 3)
        self.assertEqual(self.result.get("nonexistent", "fallback"), "fallback")
        self.assertIsNone(self.result.get("nonexistent"))

    def test_keys(self):
        k = self.result.keys()
        self.assertIn("files_changed", k)
        self.assertIn("diff_hash", k)
        self.assertIn("sanitization", k)

    def test_values(self):
        v = self.result.values()
        self.assertIn(3, v)
        self.assertIn("sha256:deadbeef", v)

    def test_items(self):
        d = dict(self.result.items())
        self.assertEqual(d["files_changed"], 3)
        self.assertEqual(d["diff_hash"], "sha256:deadbeef")
        self.assertEqual(d["lines_removed"], 10)

    def test_entrypoint_mutation_pattern(self):
        """Simulate the dict-mutation pattern used by entrypoint.py."""
        self.result["raw_diff_hash"] = self.result.get("diff_hash", "")
        self.result["ai_diff_hash"] = "sha256:aabbcc"
        self.result["pii_shield"] = {"enabled": True, "mode": "auto"}
        self.result["sanitization"] = {"engine_name": "pii-shield"}

        self.assertEqual(self.result.raw_diff_hash, "sha256:deadbeef")
        self.assertEqual(self.result.ai_diff_hash, "sha256:aabbcc")
        self.assertEqual(self.result.pii_shield["enabled"], True)
        self.assertEqual(self.result.sanitization["engine_name"], "pii-shield")

    def test_list_default_independence(self):
        """Each instance gets its own list/dict defaults (no sharing)."""
        a = AnalysisResult()
        b = AnalysisResult()
        a.files.append({"path": "a.py"})
        self.assertEqual(len(b.files), 0)


class TestAnalysisResultWithClassifier(unittest.TestCase):
    """AnalysisResult works as input to RiskClassifier.classify()."""

    def test_classify_accepts_analysis_result(self):
        from src.risk_classifier import RiskClassifier
        classifier = RiskClassifier()
        result = AnalysisResult(
            files_changed=1,
            lines_added=5,
            files=[{"path": "README.md", "added": 5, "removed": 0, "hunks": []}],
        )
        risk = classifier.classify(result)
        self.assertIn("risk_tier", risk)
        self.assertEqual(risk["risk_tier"], "L0")


class TestAnalysisResultWithBundleGenerator(unittest.TestCase):
    """AnalysisResult works as input to BundleGenerator.create_bundle()."""

    def test_create_bundle_accepts_analysis_result(self):
        from unittest.mock import MagicMock
        from src.bundle_generator import BundleGenerator

        pr = MagicMock()
        pr.number = 1
        pr.title = "Test PR"
        pr.created_at = MagicMock()
        pr.created_at.isoformat.return_value = "2026-02-08T00:00:00Z"
        pr.user = MagicMock()
        pr.user.login = "testuser"
        pr.base = MagicMock()
        pr.base.ref = "main"
        pr.head = MagicMock()
        pr.head.ref = "feature"

        analysis = AnalysisResult(
            files_changed=2,
            lines_added=10,
            lines_removed=3,
            diff_hash="sha256:test123",
        )

        risk_result = {
            "risk_tier": "L1",
            "risk_drivers": [],
            "findings": [],
            "rationale": "Low risk",
            "scores": {},
        }

        gen = BundleGenerator()
        bundle = gen.create_bundle(
            pr=pr,
            analysis=analysis,
            risk_result=risk_result,
            repository="test/repo",
            commit_sha="abc1234",
        )

        self.assertEqual(bundle["version"], "0.2.0")
        self.assertIn("items", bundle)
        self.assertIn("immutability_proof", bundle)
        self.assertEqual(bundle["summary"]["risk_tier"], "L1")


if __name__ == "__main__":
    unittest.main()
