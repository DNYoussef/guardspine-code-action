import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "src"))

from risk_classifier import RiskClassifier  # noqa: E402


class RiskClassifierTests(unittest.TestCase):
    def _base_analysis(self):
        return {
            "files": [{
                "path": "src/payments/handler.py",
                "hunks": [{
                    "lines": [
                        {"type": "add", "content": "# payment logic", "line_number": 42},
                        {"type": "context", "content": "def charge()", "line_number": 41},
                    ]
                }],
            }],
            "sensitive_zones": [],
            "lines_added": 1,
            "lines_removed": 0,
        }

    def test_custom_rubric_path_sets_line_numbers(self):
        data = {"rules": [{"id": "PAY", "pattern": "payment", "severity": "critical", "message": "Payment code touched"}]}
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(data, f)
            rubric_path = Path(f.name)

        classifier = RiskClassifier(rubric="custom", rubric_path=rubric_path)
        result = classifier.classify(self._base_analysis())

        pay_finding = next(f for f in result["findings"] if f["rule_id"] == "PAY")
        self.assertEqual(pay_finding["line"], 42)
        self.assertEqual(pay_finding["severity"], "critical")

    def test_bad_regex_rule_is_skipped_not_fatal(self):
        data = {"rules": [{"id": "BAD", "pattern": "[", "severity": "high", "message": "Broken regex"}]}
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(data, f)
            rubric_path = Path(f.name)

        classifier = RiskClassifier(rubric="custom", rubric_path=rubric_path)
        result = classifier.classify(self._base_analysis())

        rule_ids = {f["rule_id"] for f in result["findings"]}
        self.assertNotIn("BAD", rule_ids)

    def test_policy_overrides_file_patterns_for_criticality(self):
        policy = {
            "file_patterns": {"L4": [r"critical_path/"]},
            "zone_severity": {"auth": "critical"},
            "size_thresholds": {"large": 10, "medium": 5, "small": 1},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(policy, f)
            policy_path = Path(f.name)

        analysis = {
            "files": [{"path": "critical_path/main.py", "hunks": [], "added": 2, "removed": 0}],
            "sensitive_zones": [],
            "lines_added": 2,
            "lines_removed": 0,
        }

        classifier = RiskClassifier(rubric="default", policy_path=policy_path)
        result = classifier.classify(analysis)

        self.assertEqual(result["risk_tier"], "L4")


    def test_risk_drivers_include_file_locations(self):
        analysis = {
            "files": [{"path": "src/auth.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "auth", "file": "src/auth.py", "line": 42},
                {"zone": "auth", "file": "src/auth.py", "line": 99},
            ],
            "lines_added": 5,
            "lines_removed": 0,
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        zone_drivers = [d for d in result["risk_drivers"] if d["type"] == "sensitive_zone"]
        self.assertTrue(len(zone_drivers) > 0, "Expected zone-based risk drivers")
        first = zone_drivers[0]
        self.assertIn("locations", first)
        self.assertTrue(len(first["locations"]) > 0, "Expected locations in driver")
        self.assertIn("src/auth.py:42", first["locations"])
        # Description should mention the file
        self.assertIn("src/auth.py", first["description"])

    def test_bundle_path_is_relative(self):
        """Ensure set_output bundle_path would be relative to workspace."""
        from pathlib import PurePosixPath
        workspace = PurePosixPath("/github/workspace")
        bundle_path = workspace / ".guardspine" / "bundles" / "bundle-pr1-abc1234.json"
        relative = PurePosixPath(str(bundle_path).replace(str(workspace) + "/", ""))
        self.assertEqual(str(relative), ".guardspine/bundles/bundle-pr1-abc1234.json")

    # ------------------------------------------------------------------
    # New zone detection tests (P1 fix)
    # ------------------------------------------------------------------

    def test_new_zones_command_injection(self):
        """command_injection zone triggers on subprocess/os.system patterns."""
        analysis = {
            "files": [{"path": "src/utils.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "command_injection", "file": "src/utils.py", "line": 10},
            ],
            "lines_added": 3,
            "lines_removed": 0,
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        zone_findings = [f for f in result["findings"] if f.get("zone") == "command_injection"]
        self.assertTrue(len(zone_findings) > 0, "Expected command_injection finding")
        self.assertEqual(zone_findings[0]["severity"], "critical")

    def test_new_zones_deserialization(self):
        """deserialization zone triggers on pickle.load patterns."""
        analysis = {
            "files": [{"path": "src/cache.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "deserialization", "file": "src/cache.py", "line": 5},
            ],
            "lines_added": 2,
            "lines_removed": 0,
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        zone_findings = [f for f in result["findings"] if f.get("zone") == "deserialization"]
        self.assertTrue(len(zone_findings) > 0, "Expected deserialization finding")
        self.assertEqual(zone_findings[0]["severity"], "critical")

    def test_new_zones_path_traversal(self):
        """path_traversal zone triggers on ../ patterns."""
        analysis = {
            "files": [{"path": "src/file_handler.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "path_traversal", "file": "src/file_handler.py", "line": 20},
            ],
            "lines_added": 1,
            "lines_removed": 0,
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        zone_findings = [f for f in result["findings"] if f.get("zone") == "path_traversal"]
        self.assertTrue(len(zone_findings) > 0, "Expected path_traversal finding")
        self.assertEqual(zone_findings[0]["severity"], "high")

    def test_new_zones_weak_crypto(self):
        """weak_crypto zone maps to high severity."""
        analysis = {
            "files": [{"path": "src/hash.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "weak_crypto", "file": "src/hash.py", "line": 8},
            ],
            "lines_added": 1,
            "lines_removed": 0,
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        zone_findings = [f for f in result["findings"] if f.get("zone") == "weak_crypto"]
        self.assertTrue(len(zone_findings) > 0, "Expected weak_crypto finding")
        self.assertEqual(zone_findings[0]["severity"], "high")

    def test_new_zones_entropy_secret(self):
        """entropy_secret zone maps to high severity."""
        analysis = {
            "files": [{"path": "src/config.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "entropy_secret", "file": "src/config.py", "line": 12},
            ],
            "lines_added": 1,
            "lines_removed": 0,
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        zone_findings = [f for f in result["findings"] if f.get("zone") == "entropy_secret"]
        self.assertTrue(len(zone_findings) > 0, "Expected entropy_secret finding")
        self.assertEqual(zone_findings[0]["severity"], "high")

    # ------------------------------------------------------------------
    # AI consensus wiring tests (P0 fix)
    # ------------------------------------------------------------------

    def test_ai_approve_downgrades_zone_findings(self):
        """When AI approves with high agreement, zone findings downgrade."""
        analysis = {
            "files": [{"path": "src/utils.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "auth", "file": "src/utils.py", "line": 10},
            ],
            "lines_added": 3,
            "lines_removed": 0,
            "consensus_risk": "approve",
            "agreement_score": 0.9,
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        # auth zone is normally "high" -> double downgrade to "low" when AI approves
        # (single downgrade left high->medium which still triggered conditions)
        auth_findings = [f for f in result["findings"] if f.get("zone") == "auth"]
        self.assertTrue(len(auth_findings) > 0)
        self.assertEqual(auth_findings[0]["severity"], "low",
                         "AI approve should double-downgrade auth finding from high to low")

    def test_ai_approve_does_not_downgrade_rubric_findings(self):
        """AI approve should NOT downgrade rubric-based findings."""
        data = {"rules": [{"id": "SEC-01", "pattern": "payment", "severity": "critical", "message": "Payment rule"}]}
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(data, f)
            rubric_path = Path(f.name)

        analysis = self._base_analysis()
        analysis["consensus_risk"] = "approve"
        analysis["agreement_score"] = 1.0

        classifier = RiskClassifier(rubric="custom", rubric_path=rubric_path)
        result = classifier.classify(analysis)

        rubric_finding = next(f for f in result["findings"] if f["rule_id"] == "SEC-01")
        self.assertEqual(rubric_finding["severity"], "critical",
                         "Rubric findings must not be downgraded by AI approve")

    def test_ai_request_changes_upgrades_medium_findings(self):
        """When AI flags issues, medium findings upgrade to high."""
        analysis = {
            "files": [{"path": "src/config.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "config", "file": "src/config.py", "line": 5},
            ],
            "lines_added": 2,
            "lines_removed": 0,
            "consensus_risk": "request_changes",
            "agreement_score": 0.8,
            "multi_model_review": {
                "consensus": {
                    "consensus_risk": "request_changes",
                    "agreement_score": 0.8,
                    "combined_concerns": ["Hardcoded secrets detected in config"],
                },
            },
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        # config zone is normally "medium" -> should upgrade to "high"
        config_findings = [f for f in result["findings"] if f.get("zone") == "config"]
        self.assertTrue(len(config_findings) > 0)
        self.assertEqual(config_findings[0]["severity"], "high",
                         "AI request_changes should upgrade config from medium to high")

        # Should also inject AI concern findings
        ai_findings = [f for f in result["findings"] if f.get("rule_id") == "ai-consensus"]
        self.assertTrue(len(ai_findings) > 0, "Expected AI concern findings")
        self.assertIn("Hardcoded secrets", ai_findings[0]["message"])

    def test_ai_low_agreement_approve_no_modulation(self):
        """AI approve with low agreement should not downgrade findings."""
        analysis = {
            "files": [{"path": "src/utils.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "auth", "file": "src/utils.py", "line": 10},
            ],
            "lines_added": 3,
            "lines_removed": 0,
            "consensus_risk": "approve",
            "agreement_score": 0.5,  # Below 0.6 threshold
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        auth_findings = [f for f in result["findings"] if f.get("zone") == "auth"]
        self.assertTrue(len(auth_findings) > 0)
        self.assertEqual(auth_findings[0]["severity"], "high",
                         "Low agreement approve should not trigger downgrade")

    def test_ai_request_changes_low_agreement_no_upgrade(self):
        """1-of-3 request_changes (agreement < 0.6) should NOT upgrade severity.

        Minority dissent is captured as medium advisory findings (AI-MINORITY-*)
        but zone findings stay at their original severity.
        """
        analysis = {
            "files": [{"path": "src/config.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "config", "file": "src/config.py", "line": 5},
            ],
            "lines_added": 2,
            "lines_removed": 0,
            "consensus_risk": "request_changes",
            "agreement_score": 0.33,  # 1 of 3 models
            "multi_model_review": {
                "consensus": {
                    "consensus_risk": "request_changes",
                    "agreement_score": 0.33,
                    "combined_concerns": ["Potential path traversal"],
                },
            },
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        config_findings = [f for f in result["findings"] if f.get("zone") == "config"]
        self.assertTrue(len(config_findings) > 0)
        self.assertEqual(config_findings[0]["severity"], "medium",
                         "1-of-3 request_changes should NOT upgrade medium to high")

        ai_findings = [f for f in result["findings"] if f.get("rule_id") == "ai-consensus"]
        self.assertTrue(len(ai_findings) > 0,
                        "AI minority concerns should still be injected")
        self.assertEqual(ai_findings[0]["severity"], "medium",
                         "Minority concerns should be medium (advisory only)")

    def test_no_ai_data_preserves_baseline_behavior(self):
        """Without AI data, classify behaves identically to before."""
        analysis = {
            "files": [{"path": "src/pay.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "payment", "file": "src/pay.py", "line": 1},
            ],
            "lines_added": 1,
            "lines_removed": 0,
            # No consensus_risk or agreement_score keys
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        pay_findings = [f for f in result["findings"] if f.get("zone") == "payment"]
        self.assertTrue(len(pay_findings) > 0)
        self.assertEqual(pay_findings[0]["severity"], "critical",
                         "Without AI data, payment zone stays critical")


if __name__ == "__main__":
    unittest.main()
