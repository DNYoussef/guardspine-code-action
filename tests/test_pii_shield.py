"""Tests for provider-first PII-Shield integration behavior."""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pii_shield import PIIShieldClient, PIIShieldError


class TestEndpointValidation(unittest.TestCase):
    """H7: SSRF prevention via URL validation on pii_shield_endpoint."""

    def test_rejects_cloud_metadata_ip(self):
        with self.assertRaises(ValueError, msg="cloud metadata"):
            PIIShieldClient(
                enabled=True, mode="remote",
                endpoint="http://169.254.169.254/latest/meta-data/",
            )

    def test_rejects_google_metadata_host(self):
        with self.assertRaises(ValueError, msg="cloud metadata"):
            PIIShieldClient(
                enabled=True, mode="remote",
                endpoint="http://metadata.google.internal/computeMetadata/v1/",
            )

    def test_rejects_private_ip(self):
        with self.assertRaises(ValueError, msg="private IP"):
            PIIShieldClient(
                enabled=True, mode="remote",
                endpoint="http://10.0.0.1/shield",
            )

    def test_rejects_192_168_private_ip(self):
        with self.assertRaises(ValueError, msg="private IP"):
            PIIShieldClient(
                enabled=True, mode="remote",
                endpoint="http://192.168.1.1/shield",
            )

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError, msg="http(s)"):
            PIIShieldClient(
                enabled=True, mode="remote",
                endpoint="ftp://shield.example.com/api",
            )

    def test_allows_valid_https_endpoint(self):
        client = PIIShieldClient(
            enabled=True, mode="remote",
            endpoint="https://shield.example.com/api/sanitize",
        )
        self.assertEqual(client.endpoint, "https://shield.example.com/api/sanitize")

    def test_allows_hostname_not_ip(self):
        client = PIIShieldClient(
            enabled=True, mode="remote",
            endpoint="http://pii-shield.internal.corp:8080/v1",
        )
        self.assertEqual(client.endpoint, "http://pii-shield.internal.corp:8080/v1")

    def test_none_endpoint_skips_validation(self):
        client = PIIShieldClient(enabled=True, mode="auto", endpoint=None)
        self.assertIsNone(client.endpoint)


class TestPIIShieldModes(unittest.TestCase):
    def test_disabled_mode_passthrough(self):
        text = "secret = 'abc123'\n"
        client = PIIShieldClient(enabled=False)
        result = client.sanitize_text(text)

        self.assertEqual(result.mode, "disabled")
        self.assertFalse(result.changed)
        self.assertEqual(result.sanitized_text, text)

    def test_local_mode_is_explicit_passthrough(self):
        diff = "+email='alice@example.com'\n"
        client = PIIShieldClient(enabled=True, mode="local")
        result = client.sanitize_diff(diff)

        self.assertEqual(result.mode, "local")
        self.assertEqual(result.provider, "passthrough")
        self.assertFalse(result.changed)
        self.assertEqual(result.sanitized_text, diff)
        self.assertIn("local mode is passthrough", result.to_metadata()["details"].get("warning", ""))

    def test_remote_mode_without_endpoint_fail_open_passthrough(self):
        diff = "+token='abc'\n"
        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint=None,
            fail_closed=False,
        )

        result = client.sanitize_diff(diff)
        self.assertEqual(result.mode, "remote")
        self.assertFalse(result.changed)
        self.assertEqual(result.sanitized_text, diff)

    def test_remote_mode_without_endpoint_defaults_fail_closed(self):
        client = PIIShieldClient(enabled=True, mode="remote", endpoint=None)

        with self.assertRaises(PIIShieldError):
            client.sanitize_diff("+email='alice@example.com'\n")

    def test_remote_mode_without_endpoint_fail_closed_raises(self):
        client = PIIShieldClient(enabled=True, mode="remote", endpoint=None, fail_closed=True)
        with self.assertRaises(PIIShieldError):
            client.sanitize_diff("+email='alice@example.com'\n")


class TestPIIShieldRemoteBehavior(unittest.TestCase):
    @patch("pii_shield.requests.post")
    def test_remote_mode_parses_redactions_and_signals(self, mock_post):
        diff = "+email='alice@example.com'\n+api_key='sk_live_123'\n"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "provider": "pii-shield-remote",
            "sanitized_text": "+email='[HIDDEN:e1]'\n+api_key='[HIDDEN:k1]'\n",
            "redactions_by_type": {"email": 1, "api_key": 1},
            "redaction_count": 2,
            "detections": [
                {"category": "email", "file": "app.py", "line": 1, "text": "alice@example.com"},
                {"category": "api_key", "file": "app.py", "line": 2, "text": "sk_live_123"},
            ],
            "schema_version": "2026-01",
        }
        mock_post.return_value = mock_response

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
            api_key="k",
            timeout_seconds=7.5,
        )
        result = client.sanitize_diff(diff)

        self.assertTrue(result.changed)
        self.assertEqual(result.redaction_count, 2)
        self.assertEqual(result.redactions_by_type, {"email": 1, "api_key": 1})
        self.assertEqual(result.provider, "pii-shield-remote")

        zones = result.to_sensitive_zones()
        self.assertEqual(len(zones), 2)
        self.assertEqual({z["zone"] for z in zones}, {"pii", "entropy_secret"})

        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["timeout"], 7.5)
        self.assertEqual(kwargs["json"]["input_format"], "diff")
        self.assertTrue(kwargs["json"]["include_findings"])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer k")

    @patch("pii_shield.requests.post")
    def test_remote_mode_fail_closed_raises(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout("timeout")
        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://example.invalid/shield",
            fail_closed=True,
        )

        with self.assertRaises(PIIShieldError):
            client.sanitize_diff("+email='alice@example.com'\n")

    @patch("pii_shield.requests.post")
    def test_remote_redirects_are_rejected(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 302
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
            fail_closed=True,
        )

        with self.assertRaises(PIIShieldError):
            client.sanitize_diff("+email='alice@example.com'\n")
        self.assertFalse(mock_post.call_args.kwargs["allow_redirects"])

    @patch("pii_shield.requests.post")
    def test_auto_mode_fail_open_passthrough_on_remote_error(self, mock_post):
        mock_post.side_effect = requests.exceptions.ConnectionError("offline")
        client = PIIShieldClient(
            enabled=True,
            mode="auto",
            endpoint="https://example.invalid/shield",
            fail_closed=False,
        )

        raw = "+email='alice@example.com'\n"
        result = client.sanitize_diff(raw)

        self.assertEqual(result.mode, "auto")
        self.assertEqual(result.provider, "passthrough")
        self.assertFalse(result.changed)
        self.assertEqual(result.sanitized_text, raw)
        self.assertIn("remote_error", result.to_metadata()["details"])

    @patch("pii_shield.requests.post")
    def test_auto_mode_remote_error_defaults_fail_closed(self, mock_post):
        mock_post.side_effect = requests.exceptions.ConnectionError("offline")
        client = PIIShieldClient(
            enabled=True,
            mode="auto",
            endpoint="https://example.invalid/shield",
        )

        with self.assertRaises(PIIShieldError):
            client.sanitize_diff("+email='alice@example.com'\n")


class TestPIIShieldJsonSanitization(unittest.TestCase):
    @patch("pii_shield.requests.post")
    def test_sanitize_json_document_returns_parsed_structure(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "provider": "pii-shield-remote",
            "sanitized_text": "{\"message\":\"contact [HIDDEN:e1]\"}",
            "redaction_count": 1,
            "redactions_by_type": {"email": 1},
        }
        mock_post.return_value = mock_response

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
        )
        original = {"message": "contact alice@example.com"}

        sanitized, result = client.sanitize_json_document(original, purpose="bundle")
        self.assertTrue(result.changed)
        self.assertEqual(sanitized["message"], "contact [HIDDEN:e1]")

    @patch("pii_shield.requests.post")
    def test_sanitize_json_document_fail_open_on_parse_error(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "provider": "pii-shield-remote",
            "sanitized_text": "not-json",
            "redaction_count": 1,
            "redactions_by_type": {"token": 1},
        }
        mock_post.return_value = mock_response

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
            fail_closed=False,
        )
        original = {"token": "secret"}

        sanitized, result = client.sanitize_json_document(original, purpose="bundle")
        self.assertEqual(sanitized, original)
        self.assertIn("parse_error", result.to_metadata()["details"])

    @patch("pii_shield.requests.post")
    def test_sanitize_json_document_fail_closed_on_parse_error(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "provider": "pii-shield-remote",
            "sanitized_text": "not-json",
            "redaction_count": 1,
            "redactions_by_type": {"token": 1},
        }
        mock_post.return_value = mock_response

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
            fail_closed=True,
        )

        with self.assertRaises(PIIShieldError):
            client.sanitize_json_document({"token": "secret"}, purpose="bundle")


class TestHashFieldPreservation(unittest.TestCase):
    """C1 regression: hash/signature fields must survive PII-Shield sanitization."""

    @patch("pii_shield.requests.post")
    def test_hash_fields_preserved_after_sanitization(self, mock_post):
        """Hash fields should be extracted before remote call and reinjected after."""
        bundle = {
            "chain_hash": "sha256:aabbccdd" + "ee" * 28,
            "content_hash": "sha256:11223344" + "55" * 28,
            "root_hash": "sha256:deadbeef" + "00" * 28,
            "signature_value": "base64:MEUCIQC" + "A" * 80,
            "public_key_id": "key-2026-02-07",
            "previous_hash": "sha256:cafebabe" + "ff" * 28,
            "final_hash": "sha256:f1f2f3f4" + "ab" * 28,
            "message": "contact alice@example.com for details",
            "nested": {
                "inner_hash": "sha256:nested00" + "11" * 28,
                "description": "call 555-0100",
            },
        }

        # Simulate remote endpoint redacting high-entropy + PII strings
        def fake_post(url, json=None, headers=None, timeout=None, allow_redirects=None):
            text = json["text"]
            # Redact anything that looks like a hash or PII
            import re
            redacted = re.sub(r"sha256:[0-9a-f]{64}", "[REDACTED:hash]", text)
            redacted = re.sub(r"base64:\S+", "[REDACTED:entropy]", redacted)
            redacted = re.sub(r"key-\S+", "[REDACTED:key]", redacted)
            redacted = redacted.replace("alice@example.com", "[REDACTED:email]")
            redacted = redacted.replace("555-0100", "[REDACTED:phone]")

            resp = Mock()
            resp.status_code = 200
            resp.raise_for_status.return_value = None
            resp.json.return_value = {
                "provider": "pii-shield-remote",
                "sanitized_text": redacted,
                "redaction_count": 2,
                "redactions_by_type": {"email": 1, "phone": 1},
            }
            return resp

        mock_post.side_effect = fake_post

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
        )

        sanitized, result = client.sanitize_json_document(bundle, purpose="bundle")

        # Hash fields must be intact
        self.assertEqual(sanitized["chain_hash"], bundle["chain_hash"])
        self.assertEqual(sanitized["content_hash"], bundle["content_hash"])
        self.assertEqual(sanitized["root_hash"], bundle["root_hash"])
        self.assertEqual(sanitized["signature_value"], bundle["signature_value"])
        self.assertEqual(sanitized["public_key_id"], bundle["public_key_id"])
        self.assertEqual(sanitized["previous_hash"], bundle["previous_hash"])
        self.assertEqual(sanitized["final_hash"], bundle["final_hash"])
        self.assertEqual(sanitized["nested"]["inner_hash"], bundle["nested"]["inner_hash"])

        # PII fields should still be redacted
        self.assertNotEqual(sanitized["message"], bundle["message"])
        self.assertIn("REDACTED", sanitized["message"])

    @patch("pii_shield.requests.post")
    def test_hash_fields_not_sent_to_remote(self, mock_post):
        """The JSON sent to the remote endpoint must NOT contain hash field values."""
        bundle = {
            "chain_hash": "sha256:aabbccdd" + "ee" * 28,
            "message": "hello world",
        }

        captured_payload = {}

        def capture_post(url, json=None, headers=None, timeout=None, allow_redirects=None):
            captured_payload["text"] = json["text"]
            resp = Mock()
            resp.status_code = 200
            resp.raise_for_status.return_value = None
            resp.json.return_value = {
                "provider": "pii-shield-remote",
                "sanitized_text": json["text"],  # no changes
                "redaction_count": 0,
                "redactions_by_type": {},
            }
            return resp

        mock_post.side_effect = capture_post

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
        )

        sanitized, _ = client.sanitize_json_document(bundle, purpose="bundle")

        # The hash value must NOT appear in the payload sent to remote
        self.assertNotIn("aabbccdd", captured_payload["text"])
        # But it must be present in the returned document
        self.assertEqual(sanitized["chain_hash"], bundle["chain_hash"])


class TestSafeRegexList(unittest.TestCase):
    """PII-Shield v1.2.0 safe_regex_list whitelist support."""

    @patch("pii_shield.requests.post")
    def test_safe_regex_list_forwarded_in_payload(self, mock_post):
        """safe_regex_list JSON is included in remote request payload."""
        captured = {}

        def capture_post(url, json=None, headers=None, timeout=None, allow_redirects=None):
            captured["payload"] = json
            resp = Mock()
            resp.status_code = 200
            resp.raise_for_status.return_value = None
            resp.json.return_value = {
                "provider": "pii-shield-remote",
                "sanitized_text": json["text"],
                "redaction_count": 0,
                "redactions_by_type": {},
            }
            return resp

        mock_post.side_effect = capture_post

        regex_json = '[{"pattern": "^[a-f0-9]{40,64}$", "name": "SafeGitSHA"}]'
        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
            safe_regex_list=regex_json,
        )
        client.sanitize_text("sha256:aabbccdd" + "ee" * 28)

        self.assertIn("safe_regex_list", captured["payload"])
        self.assertEqual(len(captured["payload"]["safe_regex_list"]), 1)
        self.assertEqual(captured["payload"]["safe_regex_list"][0]["name"], "SafeGitSHA")

    @patch("pii_shield.requests.post")
    def test_default_safe_regex_list_sent_when_none_configured(self, mock_post):
        """Default safe_regex_list (hash field whitelist) is sent when not explicitly configured."""
        captured = {}

        def capture_post(url, json=None, headers=None, timeout=None, allow_redirects=None):
            captured["payload"] = json
            resp = Mock()
            resp.status_code = 200
            resp.raise_for_status.return_value = None
            resp.json.return_value = {
                "provider": "pii-shield-remote",
                "sanitized_text": json["text"],
                "redaction_count": 0,
                "redactions_by_type": {},
            }
            return resp

        mock_post.side_effect = capture_post

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
        )
        client.sanitize_text("hello world")

        self.assertIn("safe_regex_list", captured["payload"])
        names = [r["name"] for r in captured["payload"]["safe_regex_list"]]
        self.assertIn("HashFieldSHA256", names)

    @patch("pii_shield.requests.post")
    def test_safe_regex_list_invalid_json_ignored(self, mock_post):
        """Invalid JSON in safe_regex_list is silently ignored."""
        captured = {}

        def capture_post(url, json=None, headers=None, timeout=None, allow_redirects=None):
            captured["payload"] = json
            resp = Mock()
            resp.status_code = 200
            resp.raise_for_status.return_value = None
            resp.json.return_value = {
                "provider": "pii-shield-remote",
                "sanitized_text": json["text"],
                "redaction_count": 0,
                "redactions_by_type": {},
            }
            return resp

        mock_post.side_effect = capture_post

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
            safe_regex_list="not valid json {{",
        )
        client.sanitize_text("hello world")

        self.assertNotIn("safe_regex_list", captured["payload"])

    def test_safe_regex_list_env_var_set(self):
        """PII_SAFE_REGEX_LIST env var should be readable after client init."""
        import os
        regex_json = '[{"pattern": "_hash$", "name": "HashFieldSuffix"}]'
        os.environ["PII_SAFE_REGEX_LIST"] = regex_json
        try:
            self.assertEqual(os.environ["PII_SAFE_REGEX_LIST"], regex_json)
        finally:
            del os.environ["PII_SAFE_REGEX_LIST"]


class TestDefaultSafeRegexList(unittest.TestCase):
    """Default safe_regex_list should whitelist SHA-256 hash fields."""

    @patch("pii_shield.requests.post")
    def test_default_safe_regex_sent_when_none_provided(self, mock_post):
        """When no safe_regex_list is provided, the default whitelist is sent."""
        captured = {}

        def capture_post(url, json=None, headers=None, timeout=None, allow_redirects=None):
            captured["payload"] = json
            resp = Mock()
            resp.status_code = 200
            resp.raise_for_status.return_value = None
            resp.json.return_value = {
                "provider": "pii-shield-remote",
                "sanitized_text": json["text"],
                "redaction_count": 0,
                "redactions_by_type": {},
            }
            return resp

        mock_post.side_effect = capture_post

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
        )
        client.sanitize_text("content_hash = 'aabb' * 32")

        self.assertIn("safe_regex_list", captured["payload"])
        names = [r["name"] for r in captured["payload"]["safe_regex_list"]]
        self.assertIn("HashFieldSHA256", names)
        self.assertIn("BareHexSHA256", names)

    @patch("pii_shield.requests.post")
    def test_custom_safe_regex_overrides_default(self, mock_post):
        """When user provides safe_regex_list, it replaces the default."""
        captured = {}

        def capture_post(url, json=None, headers=None, timeout=None, allow_redirects=None):
            captured["payload"] = json
            resp = Mock()
            resp.status_code = 200
            resp.raise_for_status.return_value = None
            resp.json.return_value = {
                "provider": "pii-shield-remote",
                "sanitized_text": json["text"],
                "redaction_count": 0,
                "redactions_by_type": {},
            }
            return resp

        mock_post.side_effect = capture_post

        custom = '[{"pattern": "^custom$", "name": "Custom"}]'
        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
            safe_regex_list=custom,
        )
        client.sanitize_text("hello world")

        self.assertIn("safe_regex_list", captured["payload"])
        names = [r["name"] for r in captured["payload"]["safe_regex_list"]]
        self.assertEqual(names, ["Custom"])
        self.assertNotIn("HashFieldSHA256", names)


if __name__ == "__main__":
    unittest.main()
