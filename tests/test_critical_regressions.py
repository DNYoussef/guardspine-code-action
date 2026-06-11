"""
Critical/high regression tests that must pass before release.

These tests are intentionally strict. They lock behavior for:
  - rubric loading correctness
  - decision integrity (provable vs opinion findings)
  - deliberation model identity/order
  - false positives from remediation diffs
  - runtime security hardening expectations
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from src.analyzer import DiffAnalyzer
from src.bundle_generator import BundleGenerator
from src.risk_classifier import RiskClassifier
from entrypoint import _map_findings, fetch_pr_diff, main, set_output
from src.decision_engine import DecisionEngine


class TestActionSupplyChainRegressions(unittest.TestCase):
    def test_action_uses_checked_out_dockerfile_not_mutable_main_image(self):
        action_yml = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("image: 'Dockerfile'", action_yml)
        self.assertNotIn("ghcr.io/dnyoussef/codeguard-action:main", action_yml)


class TestRubricSchemaCompatibility(unittest.TestCase):
    def test_builtin_security_rubric_with_patterns_is_compiled(self):
        rubric_path = ROOT / "rubrics" / "builtin" / "security.yaml"
        classifier = RiskClassifier(rubric="custom", rubric_path=rubric_path)
        compiled = [r for r in classifier.rubric_rules if r.get("compiled")]
        self.assertGreater(
            len(compiled),
            0,
            "Security rubric rules must compile from shipped YAML schema",
        )


class TestDecisionIntegrityRegressions(unittest.TestCase):
    def test_ai_consensus_finding_with_provable_false_stays_nonprovable(self):
        mapped = _map_findings([
            {
                "severity": "high",
                "message": "AI concern",
                "rule_id": "ai-consensus",
                "provable": False,
            }
        ])
        self.assertFalse(
            mapped[0].provable,
            "AI consensus findings are opinionated and must not be marked provable",
        )

    def test_l4_risk_cannot_end_as_merge(self):
        diff = (
            "diff --git a/app.py b/app.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-def run(cmd):\n"
            "-    os.system(cmd)\n"
            "+def run(cmd):\n"
            "+    return subprocess.run([cmd], check=True)\n"
        )

        analysis = DiffAnalyzer(ai_review=False).analyze(diff)
        analysis["consensus_risk"] = "approve"
        analysis["agreement_score"] = 1.0

        risk = RiskClassifier().classify(analysis)
        packet = DecisionEngine("standard").decide(_map_findings(risk["findings"]))

        self.assertFalse(
            risk["risk_tier"] == "L4" and packet.decision == "merge",
            "L4 risk with security findings must not produce MERGE",
        )

    def test_model_approve_cannot_soften_deterministic_l3_to_merge(self):
        analysis = {
            "files": [{"path": "src/auth/session.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "auth", "file": "src/auth/session.py", "line": 42},
            ],
            "lines_added": 2,
            "lines_removed": 0,
            "consensus_risk": "approve",
            "agreement_score": 1.0,
        }

        risk = RiskClassifier().classify(analysis)
        packet = DecisionEngine("standard").decide(_map_findings(risk["findings"]))
        auth_finding = next(f for f in risk["findings"] if f.get("zone") == "auth")

        self.assertEqual(risk["risk_tier"], "L3")
        self.assertEqual(auth_finding["severity"], "high")
        self.assertNotEqual(
            packet.decision,
            "merge",
            "Model approval must not turn deterministic L3 findings into MERGE",
        )

    def test_ai_opinion_only_findings_cannot_hard_block(self):
        packet = DecisionEngine("standard").decide(_map_findings([
            {
                "severity": "critical",
                "message": "AI concern",
                "rule_id": "ai-consensus",
                "provable": False,
            }
        ]))
        self.assertNotEqual(packet.decision, "block")


class TestDeliberationOrderingRegression(unittest.TestCase):
    def test_parallel_review_preserves_provider_model_order(self):
        analyzer = DiffAnalyzer(openrouter_key="dummy", ai_review=True)
        providers = [("openrouter", "m1"), ("openrouter", "m2"), ("openrouter", "m3")]

        delays = {"m1": 0.3, "m2": 0.1, "m3": 0.2}

        def fake_get(provider, model, diff, zones, rubric, use_rubric):
            time.sleep(delays[model])
            return {
                "model_name": model,
                "provider": provider,
                "summary": "",
                "intent": "",
                "concerns": [],
                "risk_assessment": "approve",
                "confidence": 0.9,
                "rubric_scores": {},
            }

        analyzer._get_model_review = fake_get
        reviews = analyzer._parallel_review(providers, "diff", [], "default", False)
        got = [(r.get("provider"), r.get("model_name")) for r in reviews]

        self.assertEqual(
            got,
            providers,
            "Round outputs must preserve provider/model ordering for cross-check identity",
        )


class TestAnalyzerFalsePositiveRegressions(unittest.TestCase):
    def test_remediation_diff_does_not_keep_command_injection_zone(self):
        diff = (
            "diff --git a/app.py b/app.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-def run(cmd):\n"
            "-    os.system(cmd)\n"
            "+def run(cmd):\n"
            "+    return subprocess.run([cmd], check=True)\n"
        )

        analysis = DiffAnalyzer(ai_review=False).analyze(diff)
        zones = [z.get("zone") for z in analysis.get("sensitive_zones", [])]
        self.assertNotIn(
            "command_injection",
            zones,
            "Safe remediation should not be flagged as command injection",
        )

    def test_doc_file_mentions_do_not_trigger_sensitive_zones(self):
        """README.md describing auth/crypto features must not trigger zones."""
        diff = (
            "diff --git a/README.md b/README.md\n"
            "index 1111111..2222222 100644\n"
            "--- a/README.md\n"
            "+++ b/README.md\n"
            "@@ -1,1 +1,4 @@\n"
            " # MyProject\n"
            "+## Authentication\n"
            "+Supports encrypted tokens, password hashing, and API key rotation.\n"
            "+Uses SHA-256 for content verification and HMAC for signing.\n"
        )
        analysis = DiffAnalyzer(ai_review=False).analyze(diff)
        zones = [z.get("zone") for z in analysis.get("sensitive_zones", [])]
        self.assertEqual(
            zones, [],
            "Documentation files should not trigger any sensitive zone alerts",
        )

    def test_duplicate_sensitive_zones_are_deduplicated_in_findings(self):
        analysis = {
            "files": [{"path": "src/a.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "auth", "file": "src/a.py", "line": 10},
                {"zone": "auth", "file": "src/a.py", "line": 10},
            ],
            "lines_added": 1,
            "lines_removed": 0,
        }
        result = RiskClassifier().classify(analysis)
        auth = [f for f in result["findings"] if f.get("zone") == "auth"]
        self.assertEqual(len(auth), 1)


class TestRuntimeSecurityRegressions(unittest.TestCase):
    def test_fetch_pr_diff_uses_auth_headers(self):
        pr = MagicMock()
        pr.diff_url = "https://api.github.com/repos/o/r/pulls/1"

        fake_resp = MagicMock()
        fake_resp.text = "diff --git a/x b/x"
        fake_resp.raise_for_status.return_value = None

        with patch.dict(os.environ, {"INPUT_GITHUB_TOKEN": "ghs_test_token"}, clear=False):
            with patch("requests.get", return_value=fake_resp) as mock_get:
                fetch_pr_diff(pr)

        _, kwargs = mock_get.call_args
        self.assertIn("headers", kwargs, "Diff fetch must pass auth headers")
        self.assertIn("Authorization", kwargs["headers"])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer ghs_test_token")

    def test_bundle_signing_fails_closed_on_invalid_key(self):
        generator = BundleGenerator()
        with self.assertRaises(Exception):
            generator._sign_bundle({"version": "0.2.0", "signatures": []}, "not-a-pem-key")

    def test_bundle_signing_allows_explicit_insecure_fallback(self):
        generator = BundleGenerator()
        signature = generator._sign_bundle(
            {"version": "0.2.0", "signatures": []},
            "not-a-pem-key",
            allow_insecure_fallback=True,
        )
        self.assertEqual(signature["algorithm"], "hmac-sha256")

    def test_decision_engine_vendored_not_external(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertNotIn(
            "guardspine-product",
            requirements,
            "Decision engine is vendored in src/decision_engine.py, not an external dependency",
        )

    def test_set_output_uses_multiline_safe_format(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            out_path = Path(f.name)

        try:
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(out_path)}, clear=False):
                set_output("risk_drivers", "line1\nline2")
            body = out_path.read_text(encoding="utf-8")
            self.assertIn("risk_drivers<<EOF_", body)
            self.assertIn("line1\nline2", body)
        finally:
            out_path.unlink(missing_ok=True)


class TestDecisionPolicyResolutionRegression(unittest.TestCase):
    def test_main_resolves_decision_policy_relative_to_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            event_path = workspace / "event.json"
            event_path.write_text(json.dumps({"pull_request": {"number": 7}}), encoding="utf-8")
            policy_path = workspace / "custom-policy.yaml"
            policy_path.write_text(
                "name: local\nhard_block_rules: []\ncondition_rules: []\nmax_conditions: 2\n",
                encoding="utf-8",
            )

            pr = MagicMock()
            pr.number = 7

            repo = MagicMock()
            repo.get_pull.return_value = pr

            gh = MagicMock()
            gh.get_repo.return_value = repo

            analyzer_instance = MagicMock()
            analyzer_instance.analyze.return_value = {
                "files_changed": 0,
                "lines_added": 0,
                "lines_removed": 0,
                "files": [],
                "sensitive_zones": [],
                "models_used": 0,
                "consensus_risk": "",
                "agreement_score": 0.0,
            }

            classifier_instance = MagicMock()
            classifier_instance.classify.return_value = {
                "risk_tier": "L0",
                "risk_drivers": [],
                "findings": [],
                "scores": {},
                "rationale": "ok",
            }

            packet = MagicMock()
            packet.decision = "merge"
            packet.hard_blocks = []
            packet.conditions = []
            packet.advisory = []

            with patch.dict(
                os.environ,
                {
                    "GITHUB_WORKSPACE": str(workspace),
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_REPOSITORY": "o/r",
                    "GITHUB_SHA": "abc1234",
                    "GITHUB_REF": "refs/pull/7/head",
                    "INPUT_GITHUB_TOKEN": "token",
                    "INPUT_POST_COMMENT": "false",
                    "INPUT_GENERATE_BUNDLE": "false",
                    "INPUT_UPLOAD_SARIF": "false",
                    "INPUT_AI_REVIEW": "false",
                    "INPUT_AUTO_MERGE": "false",
                    "INPUT_DECISION_POLICY": "custom-policy.yaml",
                },
                clear=False,
            ):
                with patch("entrypoint.Github", return_value=gh):
                    with patch("entrypoint.fetch_pr_diff", return_value="diff --git a/x b/x\n"):
                        with patch("entrypoint.DiffAnalyzer", return_value=analyzer_instance):
                            with patch("entrypoint.RiskClassifier") as mock_classifier_cls:
                                mock_classifier_cls.RUBRICS = {"default": {}}
                                mock_classifier_cls.discover_builtin_rubrics.return_value = {}
                                mock_classifier_cls.builtin_names.return_value = {"default"}
                                mock_classifier_cls.return_value = classifier_instance
                                with patch("entrypoint.DecisionEngine") as mock_engine:
                                    mock_engine.return_value.decide.return_value = packet
                                    with patch("entrypoint.render_decision_card", return_value="card"):
                                        with self.assertRaises(SystemExit) as exit_ctx:
                                            main()

            self.assertEqual(exit_ctx.exception.code, 0)
            called_policy = mock_engine.call_args[0][0]
            self.assertEqual(
                Path(called_policy).resolve(),
                policy_path.resolve(),
                "Decision policy must resolve relative to workspace",
            )


class TestRiskPolicyValidationRegression(unittest.TestCase):
    def test_pack_style_policy_is_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("pack_id: finance-v0.9\nname: Finance\n")
            policy_path = Path(f.name)

        try:
            with self.assertRaises(ValueError):
                RiskClassifier(policy_path=policy_path)
        finally:
            policy_path.unlink(missing_ok=True)

    def test_valid_strict_policy_is_accepted(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(
                "file_patterns:\n"
                "  L4: ['payment']\n"
                "zone_severity:\n"
                "  auth: critical\n"
                "size_thresholds:\n"
                "  large: 500\n"
                "  medium: 100\n"
                "  small: 20\n"
            )
            policy_path = Path(f.name)

        try:
            classifier = RiskClassifier(policy_path=policy_path)
            self.assertEqual(classifier.zone_severity.get("auth"), "critical")
            self.assertEqual(classifier.size_thresholds["large"], 500)
        finally:
            policy_path.unlink(missing_ok=True)


class TestProvableInvariantAndTopicScoping(unittest.TestCase):
    """P1 (block only on provable) + P2 (topic-zone scoping) acceptance bar.

    Origin: GuardSpine PR #111 hard-blocked on the words crypto/auth/secrets
    in YAML COMMENT prose, because keyword zones were marked provable=True and
    the detector scanned comments in non-source files.
    """

    # --- P1: provable is the only hard-block path -------------------------

    def test_missing_provable_in_payload_defaults_nonprovable(self):
        """Acceptance: missing provable from sensitive-*/rubric payloads
        defaults non-provable. The old mapper inferred provable from rule_id."""
        mapped = _map_findings([
            {"severity": "critical", "message": "Sensitive crypto code modified",
             "rule_id": "sensitive-crypto", "zone": "crypto"},   # no 'provable'
            {"severity": "critical", "message": "Policy rule triggered",
             "rule_id": "RUBRIC-CC7.1"},                          # no 'provable'
        ])
        self.assertTrue(
            all(m.provable is False for m in mapped),
            "Missing provable must default to non-provable; a rule_id alone "
            "never grants hard-block authority",
        )

    def test_zone_and_rubric_findings_are_nonprovable(self):
        """Mutation guard (default): keyword zone findings the classifier emits
        must be non-provable. Flipping Finding.provable's default back to True
        breaks this."""
        analysis = {
            "files": [{"path": "src/crypto_util.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "crypto", "file": "src/crypto_util.py", "line": 5},
            ],
            "lines_added": 1,
            "lines_removed": 0,
        }
        risk = RiskClassifier().classify(analysis)
        zone_findings = [
            f for f in risk["findings"]
            if str(f.get("rule_id", "")).startswith("sensitive-")
        ]
        self.assertTrue(zone_findings, "expected a sensitive-crypto zone finding")
        self.assertTrue(
            all(f["provable"] is False for f in zone_findings),
            "Keyword zone findings must be non-provable",
        )

    def test_critical_keyword_finding_nonprovable_conditions_not_blocks(self):
        """Acceptance: a critical keyword finding with provable=False
        conditions/escalates but does not hard-block."""
        packet = DecisionEngine("standard").decide(_map_findings([
            {"severity": "critical", "message": "Sensitive crypto code modified",
             "rule_id": "sensitive-crypto", "zone": "crypto", "provable": False},
        ]))
        self.assertEqual(packet.decision, "merge-with-conditions")
        self.assertEqual(len(packet.hard_blocks), 0)

    def test_explicit_provable_critical_still_hard_blocks(self):
        """Acceptance + mutation guard (block path): an explicit provable=True
        critical finding MUST still hard-block. Bypassing the provable gate in
        the mapper or engine breaks this."""
        packet = DecisionEngine("standard").decide(_map_findings([
            {"severity": "critical", "message": "Deterministic detection",
             "rule_id": "real-detector", "provable": True},
        ]))
        self.assertEqual(packet.decision, "block")
        self.assertEqual(len(packet.hard_blocks), 1)

    def test_yaml_comment_keywords_do_not_block(self):
        """Acceptance: the PR #111 class. A workflow YAML whose added lines are
        comments mentioning sign/verify/secrets must not block."""
        diff = (
            "diff --git a/.github/workflows/pr-check.yml b/.github/workflows/pr-check.yml\n"
            "index 1111111..2222222 100644\n"
            "--- a/.github/workflows/pr-check.yml\n"
            "+++ b/.github/workflows/pr-check.yml\n"
            "@@ -1,1 +1,4 @@\n"
            " name: PR Check\n"
            "+          # block fires only on provable findings (forgery / secrets /\n"
            "+          # injection class). The gate must sign and verify the encrypt\n"
            "+          # path; auth refactors carry no provable danger.\n"
        )
        analysis = DiffAnalyzer(ai_review=False).analyze(diff)
        zones = [z.get("zone") for z in analysis.get("sensitive_zones", [])]
        self.assertEqual(
            zones, [], "YAML comment prose must not raise topic zones",
        )
        risk = RiskClassifier().classify(analysis)
        packet = DecisionEngine("standard").decide(_map_findings(risk["findings"]))
        self.assertNotEqual(packet.decision, "block")

    # --- P2: topic-zone scoping (source files + comments) -----------------

    def test_python_comment_keywords_do_not_raise_topic_zones(self):
        """Acceptance: Python comments do not inflate topic zones."""
        diff = (
            "diff --git a/src/app.py b/src/app.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -1,1 +1,3 @@\n"
            " def f():\n"
            "+    # this will encrypt the password and sign the auth token\n"
            "+    return 1\n"
        )
        analysis = DiffAnalyzer(ai_review=False).analyze(diff)
        zones = [z.get("zone") for z in analysis.get("sensitive_zones", [])]
        self.assertEqual(
            zones, [], "Python comment keywords must not raise topic zones",
        )

    def test_real_source_keyword_lines_still_signal(self):
        """Acceptance + mutation guard (over-suppression): real source keyword
        lines still produce tier/condition signals. Scoping that swallowed
        these would break this."""
        diff = (
            "diff --git a/src/auth.py b/src/auth.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/src/auth.py\n"
            "+++ b/src/auth.py\n"
            "@@ -1,1 +1,3 @@\n"
            " import os\n"
            "+def login(password):\n"
            "+    return encrypt(password)\n"
        )
        analysis = DiffAnalyzer(ai_review=False).analyze(diff)
        zones = set(z.get("zone") for z in analysis.get("sensitive_zones", []))
        self.assertTrue(
            {"auth", "crypto"} & zones,
            "Real source keyword lines must still raise topic zones",
        )
        risk = RiskClassifier().classify(analysis)
        packet = DecisionEngine("standard").decide(_map_findings(risk["findings"]))
        self.assertNotEqual(risk["risk_tier"], "L0")
        self.assertIn(
            packet.decision, ("merge-with-conditions", "block"),
            "A real auth/crypto source change must still escalate",
        )

    def test_danger_detector_still_scans_config_files(self):
        """Constraint: source-file scoping is TOPIC-only. A code-shaped DANGER
        pattern must still fire in a config file, so a future deterministic
        secret/injection detector is never foreclosed there."""
        diff = (
            "diff --git a/deploy.yaml b/deploy.yaml\n"
            "index 1111111..2222222 100644\n"
            "--- a/deploy.yaml\n"
            "+++ b/deploy.yaml\n"
            "@@ -1,1 +1,2 @@\n"
            " steps:\n"
            "+  run: python -c 'import os; os.system(payload)'\n"
        )
        analysis = DiffAnalyzer(ai_review=False).analyze(diff)
        zones = set(z.get("zone") for z in analysis.get("sensitive_zones", []))
        self.assertIn(
            "command_injection", zones,
            "DANGER detectors must keep scanning config files (topic-only scoping)",
        )


class TestSecretDetectorWiring(unittest.TestCase):
    """P3b: the deterministic secret detector wired end-to-end
    (analyzer -> risk_classifier -> decision engine). Restores a real
    block path for provable secrets that P1 left structurally empty.

    Fixture hygiene (amendment 5): the PEM header is assembled from split
    parts so secret scanning cannot flag this corpus.
    """

    @staticmethod
    def _pem():
        return "-----BEGIN " + "RSA PRIVATE " + "KEY-----"

    @staticmethod
    def _diff(path, added):
        body = "".join("+" + line + "\n" for line in added)
        return (
            f"diff --git a/{path} b/{path}\n"
            "index 1111111..2222222 100644\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            f"@@ -1,1 +1,{len(added) + 1} @@\n"
            " context\n"
            f"{body}"
        )

    def _decide(self, path, added):
        analysis = DiffAnalyzer(ai_review=False).analyze(self._diff(path, added))
        risk = RiskClassifier().classify(analysis)
        packet = DecisionEngine("standard").decide(_map_findings(risk["findings"]))
        return analysis, risk, packet

    def test_pem_in_source_blocks(self):
        _, _, packet = self._decide("src/config.py", [self._pem()])
        self.assertEqual(packet.decision, "block")
        self.assertGreaterEqual(len(packet.hard_blocks), 1)

    def test_pem_in_config_yaml_also_blocks(self):
        # Secret detection is NOT topic-scoped: a committed key in a .yml must
        # still block (the P2 constraint that config secrets stay detectable).
        _, _, packet = self._decide("deploy/values.yaml", [self._pem()])
        self.assertEqual(packet.decision, "block")

    def test_pem_in_test_fixture_conditions_not_blocks(self):
        # Amendment 3: a secret in a test/fixture file conditions, never blocks.
        _, _, packet = self._decide("tests/fixtures/sample_key.py", [self._pem()])
        self.assertNotEqual(packet.decision, "block")
        self.assertEqual(len(packet.hard_blocks), 0)

    def test_sha256_hash_field_does_not_block(self):
        line = "content_hash = '" + ("abcdef0123456789" * 4) + "'"
        _, _, packet = self._decide("src/bundle.py", [line])
        self.assertNotEqual(packet.decision, "block")

    def test_generic_password_assignment_conditions_not_blocks(self):
        # David's correction: generic assignment is NOT provable -> condition.
        line = "password = 'Ab3Xy9Zk7Qw2Mn5Pr8Lt'"
        _, _, packet = self._decide("src/login.py", [line])
        self.assertNotEqual(packet.decision, "block")

    def test_yaml_comment_prose_still_does_not_block(self):
        # P1+P2 regression: comment keywords still merge, even with the secret
        # detector now active on the same file.
        added = ["# this config will encrypt the password and sign the auth token"]
        _, _, packet = self._decide(".github/workflows/x.yml", added)
        self.assertNotEqual(packet.decision, "block")


if __name__ == "__main__":
    unittest.main()
