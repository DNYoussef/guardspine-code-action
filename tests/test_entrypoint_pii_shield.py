"""Integration tests for entrypoint PII-Shield plumbing."""

import hashlib
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
from src.pii_shield import PIIShieldResult


class TestEntrypointPIIShield(unittest.TestCase):
    def test_raw_diff_is_preserved_and_ai_diff_is_provider_sanitized(self):
        raw_diff = (
            "diff --git a/app.py b/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,0 +1,1 @@\n"
            "+contact = 'alice@example.com'\n"
        )
        redacted_diff = raw_diff.replace("alice@example.com", "[HIDDEN:e1]")

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            event_path = workspace / "event.json"
            event_path.write_text(json.dumps({"pull_request": {"number": 7}}), encoding="utf-8")

            pr = MagicMock()
            pr.number = 7
            pr.title = "Stub PR"
            pr.state = "open"
            pr.mergeable = True

            repo = MagicMock()
            repo.get_pull.return_value = pr

            gh = MagicMock()
            gh.get_repo.return_value = repo

            captured: dict[str, object] = {}

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
                    rubric_packs=None,
                ):
                    captured["raw"] = diff_content
                    captured["ai"] = ai_diff_content
                    return {
                        "files_changed": 1,
                        "lines_added": 1,
                        "lines_removed": 0,
                        "files": [],
                        "sensitive_zones": [
                            {"zone": "auth", "file": "app.py", "line": 1, "content_preview": "auth"}
                        ],
                        "diff_hash": "sha256:raw-diff-hash",
                        "models_used": 0,
                        "consensus_risk": "",
                        "agreement_score": 0.0,
                    }

            class StubClassifier:
                @staticmethod
                def discover_builtin_rubrics(_repo_root):
                    return {}

                @staticmethod
                def builtin_names(_repo_root):
                    return {"default"}

                def __init__(self, *args, **kwargs):
                    pass

                def rubric_prompt_packs(self):

                    # No packs: these probes are about PII sanitization,

                    # and an empty list leaves the prompt free of a

                    # governance block exactly as before.

                    return []


                def classify(self, analysis):
                    captured["analysis"] = analysis
                    return {
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

            pii_result = PIIShieldResult(
                sanitized_text=redacted_diff,
                changed=True,
                redaction_count=1,
                redactions_by_type={"email": 1},
                mode="remote",
                provider="pii-shield-test",
                input_hash="sha256:in",
                output_hash="sha256:out",
                signals=[
                    {
                        "zone": "pii",
                        "file": "app.py",
                        "line": 1,
                        "content_preview": "[HIDDEN:e1]",
                        "detector": "pii_shield",
                        "category": "email",
                    }
                ],
                metadata={"schema_version": "2026-01"},
            )
            pii_client = MagicMock()
            pii_client.sanitize_diff.return_value = pii_result

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
                    "INPUT_PII_SHIELD_ENABLED": "true",
                    "INPUT_PII_SHIELD_MODE": "remote",
                    "INPUT_PII_SHIELD_ENDPOINT": "https://shield.example/api/sanitize",
                    "INPUT_PII_SHIELD_FAIL_CLOSED": "true",
                },
                clear=False,
            ):
                with patch("entrypoint.Github", return_value=gh):
                    with patch("entrypoint.fetch_pr_diff", return_value=raw_diff):
                        with patch("entrypoint.DiffAnalyzer", StubAnalyzer):
                            with patch("entrypoint.RiskClassifier", StubClassifier):
                                with patch("entrypoint.PIIShieldClient", return_value=pii_client):
                                    with patch("entrypoint.DecisionEngine") as mock_engine:
                                        mock_engine.return_value.decide.return_value = packet
                                        with patch("entrypoint.render_decision_card", return_value="card"):
                                            with self.assertRaises(SystemExit) as exit_ctx:
                                                main()

            self.assertEqual(exit_ctx.exception.code, 0)
            self.assertIn("alice@example.com", captured["raw"])
            self.assertNotIn("alice@example.com", captured["ai"])
            self.assertIn("[HIDDEN:e1]", captured["ai"])
            pii_client.sanitize_diff.assert_called_once_with(raw_diff)

            analysis = captured["analysis"]
            self.assertIn("pii_shield", analysis)
            self.assertTrue(analysis["pii_shield"]["enabled"])
            self.assertIn("sanitization", analysis)
            self.assertEqual(analysis["sanitization"]["engine_name"], "pii-shield")
            self.assertEqual(analysis["raw_diff_hash"], "sha256:raw-diff-hash")
            expected_ai_hash = "sha256:" + hashlib.sha256(redacted_diff.encode("utf-8")).hexdigest()
            self.assertEqual(analysis["ai_diff_hash"], expected_ai_hash)

            zones = analysis["sensitive_zones"]
            zone_names = {z["zone"] for z in zones}
            self.assertEqual(zone_names, {"auth", "pii"})


class TestFailOpenOnNonNetworkError(unittest.TestCase):
    """H8: Non-network errors in sanitization stages must not exit(1) when fail-open."""

    def test_comment_sanitization_continues_on_type_error_when_fail_open(self):
        """TypeError in comment sanitization should warn and continue, not exit(1)."""
        raw_diff = (
            "diff --git a/app.py b/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,0 +1,1 @@\n"
            "+x = 1\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            event_path = workspace / "event.json"
            event_path.write_text(json.dumps({"pull_request": {"number": 9}}), encoding="utf-8")

            pr = MagicMock()
            pr.number = 9
            pr.title = "Stub PR"
            pr.state = "open"
            pr.mergeable = True

            repo = MagicMock()
            repo.get_pull.return_value = pr

            gh = MagicMock()
            gh.get_repo.return_value = repo

            class StubAnalyzer:
                def __init__(self, *args, **kwargs):
                    pass
                def analyze(self, diff_content, rubric="default", tier_override=None,
                            deliberate=False, ai_diff_content=None,
                            rubric_packs=None):
                    return {
                        "files_changed": 1, "lines_added": 1, "lines_removed": 0,
                        "files": [], "sensitive_zones": [],
                        "diff_hash": "sha256:x", "models_used": 0,
                        "consensus_risk": "", "agreement_score": 0.0,
                    }

            class StubClassifier:
                @staticmethod
                def discover_builtin_rubrics(_rr):
                    return {}
                @staticmethod
                def builtin_names(_rr):
                    return {"default"}
                def __init__(self, *args, **kwargs):
                    pass
                def rubric_prompt_packs(self):
                    # No packs: these probes are about PII sanitization,
                    # and an empty list leaves the prompt free of a
                    # governance block exactly as before.
                    return []

                def classify(self, analysis):
                    return {
                        "risk_tier": "L0", "risk_drivers": [],
                        "findings": [], "scores": {}, "rationale": "ok",
                    }

            packet = MagicMock()
            packet.decision = "merge"
            packet.hard_blocks = []
            packet.conditions = []
            packet.advisory = []

            pii_client = MagicMock()
            pii_client.sanitize_diff.return_value = PIIShieldResult(
                sanitized_text=raw_diff, changed=False, redaction_count=0,
                redactions_by_type={}, mode="remote", provider="test",
                input_hash="sha256:in", output_hash="sha256:out",
                signals=[], metadata={},
            )
            # Simulate a TypeError (non-network error) in comment sanitization
            pii_client.sanitize_text.side_effect = TypeError("unexpected None")
            pii_client.fail_closed = False

            with patch.dict(os.environ, {
                "GITHUB_WORKSPACE": str(workspace),
                "GITHUB_EVENT_PATH": str(event_path),
                "GITHUB_REPOSITORY": "o/r",
                "GITHUB_SHA": "abc1234",
                "GITHUB_REF": "refs/pull/9/head",
                "INPUT_GITHUB_TOKEN": "token",
                "INPUT_POST_COMMENT": "true",
                "INPUT_GENERATE_BUNDLE": "false",
                "INPUT_UPLOAD_SARIF": "false",
                "INPUT_AI_REVIEW": "false",
                "INPUT_AUTO_MERGE": "false",
                "INPUT_PII_SHIELD_ENABLED": "true",
                "INPUT_PII_SHIELD_MODE": "remote",
                "INPUT_PII_SHIELD_ENDPOINT": "https://shield.example/api/sanitize",
                "INPUT_PII_SHIELD_FAIL_CLOSED": "false",
                "INPUT_PII_SHIELD_SANITIZE_COMMENTS": "true",
            }, clear=False):
                with patch("entrypoint.Github", return_value=gh):
                    with patch("entrypoint.fetch_pr_diff", return_value=raw_diff):
                        with patch("entrypoint.DiffAnalyzer", StubAnalyzer):
                            with patch("entrypoint.RiskClassifier", StubClassifier):
                                with patch("entrypoint.PIIShieldClient", return_value=pii_client):
                                    with patch("entrypoint.DecisionEngine") as mock_engine:
                                        mock_engine.return_value.decide.return_value = packet
                                        with patch("entrypoint.render_decision_card", return_value="card"):
                                            with self.assertRaises(SystemExit) as ctx:
                                                main()

            # Should exit 0 (success), NOT 1
            self.assertEqual(ctx.exception.code, 0,
                             "fail-open mode must not exit(1) on non-network sanitization error")


def _make_env(workspace, event_path, **overrides):
    """Return a base env dict for PII-Shield integration tests."""
    env = {
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_REPOSITORY": "o/r",
        "GITHUB_SHA": "abc1234",
        "GITHUB_REF": "refs/pull/1/head",
        "INPUT_GITHUB_TOKEN": "token",
        "INPUT_POST_COMMENT": "false",
        "INPUT_GENERATE_BUNDLE": "false",
        "INPUT_UPLOAD_SARIF": "false",
        "INPUT_AI_REVIEW": "false",
        "INPUT_AUTO_MERGE": "false",
        "INPUT_PII_SHIELD_ENABLED": "true",
        "INPUT_PII_SHIELD_MODE": "remote",
        "INPUT_PII_SHIELD_ENDPOINT": "https://shield.example/api/sanitize",
        "INPUT_PII_SHIELD_FAIL_CLOSED": "false",
    }
    env.update(overrides)
    return env


def _make_stubs():
    """Return (StubAnalyzer, StubClassifier, decision_packet, raw_diff)."""
    raw_diff = (
        "diff --git a/app.py b/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,0 +1,1 @@\n"
        "+x = 1\n"
    )

    class StubAnalyzer:
        def __init__(self, *a, **kw):
            pass
        def analyze(self, diff_content, rubric="default", tier_override=None,
                    deliberate=False, ai_diff_content=None, rubric_packs=None):
            return {
                "files_changed": 1, "lines_added": 1, "lines_removed": 0,
                "files": [], "sensitive_zones": [],
                "diff_hash": "sha256:x", "models_used": 0,
                "consensus_risk": "", "agreement_score": 0.0,
            }

    class StubClassifier:
        @staticmethod
        def discover_builtin_rubrics(_rr):
            return {}
        @staticmethod
        def builtin_names(_rr):
            return {"default"}
        def __init__(self, *a, **kw):
            pass
        def rubric_prompt_packs(self):
            # No packs: these probes are about PII sanitization,
            # and an empty list leaves the prompt free of a
            # governance block exactly as before.
            return []

        def classify(self, analysis):
            return {
                "risk_tier": "L0", "risk_drivers": [],
                "findings": [], "scores": {}, "rationale": "ok",
            }

    packet = MagicMock()
    packet.decision = "merge"
    packet.hard_blocks = []
    packet.conditions = []
    packet.advisory = []

    return StubAnalyzer, StubClassifier, packet, raw_diff


def _make_pii_client(raw_diff):
    """Return a mock PIIShieldClient that passes diff through unchanged."""
    pii_client = MagicMock()
    pii_client.sanitize_diff.return_value = PIIShieldResult(
        sanitized_text=raw_diff, changed=False, redaction_count=0,
        redactions_by_type={}, mode="remote", provider="test",
        input_hash="sha256:in", output_hash="sha256:out",
        signals=[], metadata={},
    )
    pii_client.sanitize_text.return_value = PIIShieldResult(
        sanitized_text="sanitized-card", changed=True, redaction_count=1,
        redactions_by_type={"email": 1}, mode="remote", provider="test",
        input_hash="sha256:in2", output_hash="sha256:out2",
        signals=[], metadata={},
    )
    def _sanitize_json_side_effect(document, purpose="json_document"):
        import copy as _copy
        sanitized = _copy.deepcopy(document) if isinstance(document, (dict, list)) else document
        result = PIIShieldResult(
            sanitized_text=json.dumps(sanitized), changed=True, redaction_count=1,
            redactions_by_type={"email": 1}, mode="remote", provider="test",
            input_hash="sha256:in3", output_hash="sha256:out3",
            signals=[], metadata={},
        )
        return sanitized, result
    pii_client.sanitize_json_document.side_effect = _sanitize_json_side_effect
    return pii_client


class TestCommentSanitizationPath(unittest.TestCase):
    """M5-a: Verify sanitize_text is called on the decision card when posting comments."""

    def test_comment_sanitization_calls_sanitize_text(self):
        StubAnalyzer, StubClassifier, packet, raw_diff = _make_stubs()
        pii_client = _make_pii_client(raw_diff)

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            event_path = workspace / "event.json"
            event_path.write_text(json.dumps({"pull_request": {"number": 1}}), encoding="utf-8")

            gh = MagicMock()
            gh.get_repo.return_value.get_pull.return_value = MagicMock(
                number=1, title="PR", state="open", mergeable=True,
            )

            env = _make_env(workspace, event_path,
                            INPUT_POST_COMMENT="true",
                            INPUT_PII_SHIELD_SANITIZE_COMMENTS="true")

            with patch.dict(os.environ, env, clear=False):
                with patch("entrypoint.Github", return_value=gh), \
                     patch("entrypoint.fetch_pr_diff", return_value=raw_diff), \
                     patch("entrypoint.DiffAnalyzer", StubAnalyzer), \
                     patch("entrypoint.RiskClassifier", StubClassifier), \
                     patch("entrypoint.PIIShieldClient", return_value=pii_client), \
                     patch("entrypoint.DecisionEngine") as mock_engine, \
                     patch("entrypoint.render_decision_card", return_value="card-body"):
                    mock_engine.return_value.decide.return_value = packet
                    with self.assertRaises(SystemExit) as ctx:
                        main()

            self.assertEqual(ctx.exception.code, 0)
            pii_client.sanitize_text.assert_called_once_with(
                "card-body",
                input_format="markdown",
                include_findings=False,
                purpose="pr_comment",
            )


class TestBundleSanitizationPath(unittest.TestCase):
    """M5-b: Verify sanitize_json_document is called on the evidence bundle."""

    def test_bundle_sanitization_calls_sanitize_json_document(self):
        StubAnalyzer, StubClassifier, packet, raw_diff = _make_stubs()
        pii_client = _make_pii_client(raw_diff)

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            event_path = workspace / "event.json"
            event_path.write_text(json.dumps({"pull_request": {"number": 2}}), encoding="utf-8")

            gh = MagicMock()
            gh.get_repo.return_value.get_pull.return_value = MagicMock(
                number=2, title="PR", state="open", mergeable=True,
            )

            env = _make_env(workspace, event_path,
                            INPUT_GENERATE_BUNDLE="true",
                            INPUT_PII_SHIELD_SANITIZE_BUNDLE="true")

            with patch.dict(os.environ, env, clear=False):
                with patch("entrypoint.Github", return_value=gh), \
                     patch("entrypoint.fetch_pr_diff", return_value=raw_diff), \
                     patch("entrypoint.DiffAnalyzer", StubAnalyzer), \
                     patch("entrypoint.RiskClassifier", StubClassifier), \
                     patch("entrypoint.PIIShieldClient", return_value=pii_client), \
                     patch("entrypoint.DecisionEngine") as mock_engine, \
                     patch("entrypoint.render_decision_card", return_value="card"), \
                     patch("entrypoint.BundleGenerator") as mock_gen:
                    mock_engine.return_value.decide.return_value = packet
                    mock_gen.return_value.create_bundle.return_value = {
                        "bundle_id": "test-bundle-001",
                        "analysis_snapshot": {},
                    }
                    with self.assertRaises(SystemExit) as ctx:
                        main()

            self.assertEqual(ctx.exception.code, 0)
            pii_client.sanitize_json_document.assert_called_once()
            call_args = pii_client.sanitize_json_document.call_args
            self.assertEqual(call_args[1].get("purpose", call_args[0][1] if len(call_args[0]) > 1 else None), "evidence_bundle")


class TestSARIFSanitizationPath(unittest.TestCase):
    """M5-c: Verify sanitize_json_document is called on SARIF content."""

    def test_sarif_sanitization_calls_sanitize_json_document(self):
        StubAnalyzer, StubClassifier, packet, raw_diff = _make_stubs()
        pii_client = _make_pii_client(raw_diff)

        # Need findings to trigger SARIF path (upload_sarif requires findings)
        class FindingsClassifier:
            @staticmethod
            def discover_builtin_rubrics(_rr):
                return {}
            @staticmethod
            def builtin_names(_rr):
                return {"default"}
            def __init__(self, *a, **kw):
                pass
            def rubric_prompt_packs(self):
                # No packs: these probes are about PII sanitization,
                # and an empty list leaves the prompt free of a
                # governance block exactly as before.
                return []

            def classify(self, analysis):
                return {
                    "risk_tier": "L1", "risk_drivers": [],
                    "findings": [{"severity": "low", "zone": "general",
                                  "message": "test finding", "file": "a.py",
                                  "line": 1, "rule_id": "T001"}],
                    "scores": {}, "rationale": "ok",
                }

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            event_path = workspace / "event.json"
            event_path.write_text(json.dumps({"pull_request": {"number": 3}}), encoding="utf-8")

            gh = MagicMock()
            gh.get_repo.return_value.get_pull.return_value = MagicMock(
                number=3, title="PR", state="open", mergeable=True,
            )

            env = _make_env(workspace, event_path,
                            INPUT_UPLOAD_SARIF="true",
                            INPUT_PII_SHIELD_SANITIZE_SARIF="true")

            with patch.dict(os.environ, env, clear=False):
                with patch("entrypoint.Github", return_value=gh), \
                     patch("entrypoint.fetch_pr_diff", return_value=raw_diff), \
                     patch("entrypoint.DiffAnalyzer", StubAnalyzer), \
                     patch("entrypoint.RiskClassifier", FindingsClassifier), \
                     patch("entrypoint.PIIShieldClient", return_value=pii_client), \
                     patch("entrypoint.DecisionEngine") as mock_engine, \
                     patch("entrypoint.render_decision_card", return_value="card"), \
                     patch("entrypoint.SARIFExporter") as mock_sarif:
                    mock_engine.return_value.decide.return_value = packet
                    mock_sarif.return_value.export.return_value = {"version": "2.1.0", "runs": []}
                    with self.assertRaises(SystemExit) as ctx:
                        main()

            self.assertEqual(ctx.exception.code, 0)
            # sanitize_json_document should be called for SARIF
            sarif_calls = [
                c for c in pii_client.sanitize_json_document.call_args_list
                if "sarif" in str(c)
            ]
            self.assertTrue(len(sarif_calls) > 0, "sanitize_json_document should be called for SARIF")


if __name__ == "__main__":
    unittest.main()
