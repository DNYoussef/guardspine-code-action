"""Tests for AI diff routing behavior in DiffAnalyzer."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from analyzer import DiffAnalyzer


class TestAnalyzerAIDiffContent(unittest.TestCase):
    _RAW_DIFF = (
        "diff --git a/src/app.py b/src/app.py\n"
        "index 1111111..2222222 100644\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,0 +1,1 @@\n"
        "+email = 'alice@example.com'\n"
    )

    _SANITIZED_DIFF = _RAW_DIFF.replace("alice@example.com", "[HIDDEN:e1]")

    def _analyzer(self) -> DiffAnalyzer:
        analyzer = DiffAnalyzer(ai_review=True)
        analyzer.ai_enabled = True
        analyzer.max_models_available = 1
        return analyzer

    def test_ai_diff_content_is_used_for_model_review_input(self):
        analyzer = self._analyzer()

        with patch.object(analyzer, "_run_multi_model_review") as mock_review:
            mock_review.return_value = {
                "reviews": [],
                "models_used": 0,
                "models_failed": 0,
                "model_errors": [],
                "consensus": {"consensus_risk": "comment", "agreement_score": 1.0},
            }
            analyzer.analyze(
                self._RAW_DIFF,
                tier_override="L1",
                ai_diff_content=self._SANITIZED_DIFF,
            )

        self.assertEqual(mock_review.call_count, 1)
        self.assertEqual(mock_review.call_args.args[0], self._SANITIZED_DIFF)

    def test_raw_diff_is_used_when_ai_diff_not_provided(self):
        analyzer = self._analyzer()

        with patch.object(analyzer, "_run_multi_model_review") as mock_review:
            mock_review.return_value = {
                "reviews": [],
                "models_used": 0,
                "models_failed": 0,
                "model_errors": [],
                "consensus": {"consensus_risk": "comment", "agreement_score": 1.0},
            }
            analyzer.analyze(self._RAW_DIFF, tier_override="L1")

        self.assertEqual(mock_review.call_count, 1)
        self.assertEqual(mock_review.call_args.args[0], self._RAW_DIFF)

    def test_content_preview_redacted_when_ai_diff_provided(self):
        """C2 regression: content_preview must not leak raw PII."""
        analyzer = self._analyzer()

        with patch.object(analyzer, "_run_multi_model_review") as mock_review:
            mock_review.return_value = {
                "reviews": [],
                "models_used": 0,
                "models_failed": 0,
                "model_errors": [],
                "consensus": {"consensus_risk": "comment", "agreement_score": 1.0},
            }
            result = analyzer.analyze(
                self._RAW_DIFF,
                tier_override="L1",
                ai_diff_content=self._SANITIZED_DIFF,
            )

        zones = result["sensitive_zones"]
        self.assertTrue(len(zones) > 0, "expected at least one sensitive zone")
        for zone in zones:
            self.assertEqual(zone["content_preview"], "[REDACTED]")
            self.assertNotIn("alice@example.com", zone["content_preview"])

    def test_content_preview_shows_raw_when_no_ai_diff(self):
        """Without sanitized diff, content_preview uses the raw line."""
        analyzer = self._analyzer()

        with patch.object(analyzer, "_run_multi_model_review") as mock_review:
            mock_review.return_value = {
                "reviews": [],
                "models_used": 0,
                "models_failed": 0,
                "model_errors": [],
                "consensus": {"consensus_risk": "comment", "agreement_score": 1.0},
            }
            result = analyzer.analyze(self._RAW_DIFF, tier_override="L1")

        zones = result["sensitive_zones"]
        self.assertTrue(len(zones) > 0, "expected at least one sensitive zone")
        # At least one zone should contain the raw email in its preview
        previews = [z["content_preview"] for z in zones]
        self.assertTrue(
            any("alice@example.com" in p for p in previews),
            f"expected raw PII in previews when ai_diff_content is None, got {previews}",
        )


class TestHashFieldWhitelist(unittest.TestCase):
    """SHA-256 hash fields in evidence bundles must not trigger the crypto zone."""

    def _make_diff(self, added_line: str) -> str:
        return (
            "diff --git a/evidence.py b/evidence.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/evidence.py\n"
            "+++ b/evidence.py\n"
            "@@ -1,0 +1,1 @@\n"
            f"+{added_line}\n"
        )

    def _zones_from(self, diff: str) -> list:
        analyzer = DiffAnalyzer(ai_review=False)
        result = analyzer.analyze(diff, tier_override="L0")
        return result["sensitive_zones"]

    def test_content_hash_with_sha256_not_flagged_as_crypto(self):
        """_hash field + 64-char hex value should NOT trigger crypto zone."""
        sha = "a" * 64
        diff = self._make_diff(f'content_hash = "{sha}"')
        zones = self._zones_from(diff)
        crypto_zones = [z for z in zones if z["zone"] == "crypto"]
        self.assertEqual(crypto_zones, [], f"crypto zone should not fire for _hash field, got {crypto_zones}")

    def test_bundle_hash_with_sha256_prefix_not_flagged(self):
        """sha256:-prefixed _hash field should NOT trigger crypto zone."""
        sha = "b" * 64
        diff = self._make_diff(f'"bundle_hash": "sha256:{sha}"')
        zones = self._zones_from(diff)
        crypto_zones = [z for z in zones if z["zone"] == "crypto"]
        self.assertEqual(crypto_zones, [])

    def test_chain_hash_in_json_not_flagged(self):
        """JSON-style chain_hash assignment should NOT trigger crypto zone."""
        sha = "deadbeef" + "00" * 28
        diff = self._make_diff(f'"chain_hash": "{sha}",')
        zones = self._zones_from(diff)
        crypto_zones = [z for z in zones if z["zone"] == "crypto"]
        self.assertEqual(crypto_zones, [])

    def test_actual_crypto_operation_still_flagged(self):
        """Real crypto operations (encrypt, decrypt, etc.) must still trigger."""
        diff = self._make_diff("ciphertext = encrypt(plaintext, key)")
        zones = self._zones_from(diff)
        crypto_zones = [z for z in zones if z["zone"] == "crypto"]
        self.assertTrue(len(crypto_zones) > 0, "encrypt() should trigger crypto zone")

    def test_hash_function_call_still_flagged(self):
        """hashlib.sha256() calls are crypto operations, must still trigger."""
        diff = self._make_diff("digest = hashlib.sha256(data).hexdigest()")
        zones = self._zones_from(diff)
        crypto_zones = [z for z in zones if z["zone"] == "crypto"]
        self.assertTrue(len(crypto_zones) > 0, "hashlib.sha256() should trigger crypto zone")

    def test_non_hash_field_with_hex_still_flagged(self):
        """A field NOT ending in _hash with a hex string should still trigger."""
        sha = "c" * 64
        diff = self._make_diff(f'secret_key = "{sha}"')
        zones = self._zones_from(diff)
        # "secret_key" matches auth zone (secret, key); crypto depends on context
        auth_zones = [z for z in zones if z["zone"] == "auth"]
        self.assertTrue(len(auth_zones) > 0, "secret_key should trigger auth zone")

    def test_short_hex_in_hash_field_still_flagged(self):
        """_hash field with non-64-char hex (e.g., truncated) should still trigger crypto."""
        diff = self._make_diff('content_hash = "abcdef1234"')
        zones = self._zones_from(diff)
        crypto_zones = [z for z in zones if z["zone"] == "crypto"]
        self.assertTrue(len(crypto_zones) > 0, "short hex in _hash field should still trigger crypto zone")

    def test_other_zones_still_fire_on_hash_field_line(self):
        """Other zones (e.g., pii) should still fire even if crypto is suppressed."""
        sha = "d" * 64
        diff = self._make_diff(f'email_hash = "sha256:{sha}"  # email: alice@example.com')
        zones = self._zones_from(diff)
        crypto_zones = [z for z in zones if z["zone"] == "crypto"]
        pii_zones = [z for z in zones if z["zone"] == "pii"]
        self.assertEqual(crypto_zones, [], "crypto should be suppressed for _hash field")
        self.assertTrue(len(pii_zones) > 0, "pii zone should still fire for email on same line")


if __name__ == "__main__":
    unittest.main()
