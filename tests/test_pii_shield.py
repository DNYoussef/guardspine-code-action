"""Behavioral tests for the in-process PII-Shield client.

This file used to test the HTTP transport: SSRF endpoint validation,
DNS-rebind pinning, redirect rejection, and the request payload (including
safe_regex_list forwarding). The HTTP client was deleted on purpose --
committed in writing upstream -- so those tests fell into two groups:

DELETED, because the property died with the network call:
  - TestEndpointValidation (12 tests). Every one asserted that a hostile
    endpoint URL was refused before we dialled it. Nothing is dialled any
    more; `tests/test_wasm_only_no_http.py` proves no HTTP library is even
    imported. An SSRF test for a request that is never made protects
    nothing.
  - Connect-time IP pinning and redirect rejection, for the same reason.
  - TestSafeRegexList / TestDefaultSafeRegexList. They asserted a caller
    regex list reached the engine via the request payload. It cannot, and
    that is deliberate: in pii-shield-wasi 2.1.1 the PII_SAFE_REGEX_LIST
    variable is ignored when it parses (measured: identical output with a
    wildcard) and terminates the runtime when it does not. Either way a
    caller-supplied list can no longer influence redaction, and
    test_wasm_config.py gates that we never populate the variable.

REWRITTEN here, because only the mechanism moved:
  - Fail-open / fail-closed on engine failure (was: on network failure).
  - JSON document sanitization: structure preserved, parse errors honoured
    per fail policy.
  - Hash/signature field preservation: MORE load-bearing than before,
    because the in-process engine redacts bare SHA-256 hex on sight, so
    extract-before / reinject-after is the only thing keeping evidence
    chain hashes verifiable.

Engine failures are injected at `PIIShieldClient._redact`, the seam the
production code isolates for exactly this purpose.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.pii_shield import PIIShieldClient, PIIShieldError


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
        with self.assertWarns(DeprecationWarning):
            client = PIIShieldClient(enabled=True, mode="local")
        result = client.sanitize_diff(diff)

        self.assertEqual(result.mode, "local")
        self.assertEqual(result.provider, "passthrough")
        self.assertFalse(result.changed)
        self.assertEqual(result.sanitized_text, diff)
        self.assertIn("local mode is passthrough", result.to_metadata()["details"].get("warning", ""))

    def test_legacy_remote_mode_sanitizes_in_process(self):
        """mode='remote' is a legacy input that workflows in the wild still
        pass. It used to REQUIRE an endpoint and raise without one -- which
        is exactly what kept PII-Shield from running in production. Now it
        must sanitize in-process, endpoint or no endpoint."""
        client = PIIShieldClient(enabled=True, mode="remote")
        result = client.sanitize_diff("+email='alice@example.com'\n")

        self.assertTrue(result.changed)
        self.assertNotIn("alice@example.com", result.sanitized_text)
        self.assertEqual(result.provider, "pii-shield-wasi")


class TestEngineFailurePolicy(unittest.TestCase):
    """A sanitizer outage must be loud (fail-closed) or honestly recorded
    (fail-open) -- never a silent leak of raw text presented as sanitized.
    The transport changed from HTTP to in-process; this property did not."""

    @staticmethod
    def _broken_client(**kw):
        client = PIIShieldClient(enabled=True, **kw)
        client._redact = lambda _text: (_ for _ in ()).throw(
            RuntimeError("engine unavailable")
        )
        return client

    def test_engine_failure_defaults_fail_closed(self):
        """fail_closed is not passed here on purpose: the DEFAULT must be
        closed, or a config that never mentions the knob leaks on outage."""
        client = self._broken_client()
        with self.assertRaises(PIIShieldError):
            client.sanitize_diff("+email='alice@example.com'\n")

    def test_engine_failure_fail_open_is_recorded_passthrough(self):
        """Fail-open may pass raw text through, but the result must SAY so:
        changed=False, provider=passthrough, and the error preserved in
        metadata. Anything less lets a broken engine masquerade as a clean
        run in the evidence bundle."""
        client = self._broken_client(fail_closed=False)
        raw = "+email='alice@example.com'\n"
        result = client.sanitize_diff(raw)

        self.assertEqual(result.provider, "passthrough")
        self.assertFalse(result.changed)
        self.assertEqual(result.sanitized_text, raw)
        self.assertIn("remote_error", result.to_metadata()["details"])


class TestResultContract(unittest.TestCase):
    """The evidence bundle records what the shield claims it did. These pin
    the claims to what actually happened in-process."""

    def test_redaction_result_reports_what_happened(self):
        text = "+email='alice@example.com'\n"
        client = PIIShieldClient(enabled=True)
        result = client.sanitize_text(text)

        self.assertTrue(result.changed)
        self.assertGreaterEqual(result.redaction_count, 1)
        self.assertEqual(result.provider, "pii-shield-wasi")
        self.assertEqual(result.mode, "wasm-local")
        # Hashes are how a verifier later proves what was sanitized. They
        # must be of the actual input and actual output, not each other.
        self.assertEqual(result.input_hash, client._sha256(text))
        self.assertEqual(result.output_hash, client._sha256(result.sanitized_text))
        self.assertNotEqual(result.input_hash, result.output_hash)

    def test_clean_text_reports_unchanged(self):
        text = "+x = 1\n"
        client = PIIShieldClient(enabled=True)
        result = client.sanitize_text(text)

        self.assertFalse(result.changed)
        self.assertEqual(result.redaction_count, 0)
        self.assertEqual(result.sanitized_text, text)
        self.assertEqual(result.input_hash, result.output_hash)


class TestPIIShieldJsonSanitization(unittest.TestCase):
    """JSON documents (bundles, SARIF) must come back as structures, and a
    sanitized blob that no longer parses must honour the fail policy.
    Engine behavior is injected at _redact so the parse-error path is
    reachable deterministically."""

    def test_sanitize_json_document_returns_parsed_structure(self):
        """Real engine on purpose, and this test earned it: run against
        pii-shield-wasi 2.1.1 with the old compact separators=(",",":")
        serialization it goes RED, because the engine redacts nothing
        inside '{"k":"v"}' compact JSON -- bundle and SARIF sanitization
        was a silent no-op. The production fix is the ": " separator; this
        pins it."""
        client = PIIShieldClient(enabled=True)
        original = {"message": "contact alice@example.com"}

        sanitized, result = client.sanitize_json_document(original, purpose="bundle")
        self.assertTrue(result.changed)
        self.assertIsInstance(sanitized, dict)
        self.assertNotIn("alice@example.com", sanitized["message"])

    def test_sanitize_json_document_fail_open_on_parse_error(self):
        client = PIIShieldClient(enabled=True, fail_closed=False)
        client._redact = lambda _text: "not-json"
        original = {"token": "secret"}

        sanitized, result = client.sanitize_json_document(original, purpose="bundle")
        self.assertEqual(sanitized, original)
        self.assertIn("parse_error", result.to_metadata()["details"])

    def test_sanitize_json_document_fail_closed_on_parse_error(self):
        client = PIIShieldClient(enabled=True, fail_closed=True)
        client._redact = lambda _text: "not-json"

        with self.assertRaises(PIIShieldError):
            client.sanitize_json_document({"token": "secret"}, purpose="bundle")


class TestHashFieldPreservation(unittest.TestCase):
    """C1 regression: hash/signature fields must survive sanitization.

    This matters MORE in-process than it did over HTTP: pii-shield-wasi
    redacts bare 64-char hex on sight (measured), so without the
    extract-before / reinject-after dance every chain_hash in an evidence
    bundle would come back as [HIDDEN:...] and the bundle would no longer
    verify. These use the REAL engine -- a mock that politely skips hashes
    would hide exactly the failure this guards against.
    """

    BUNDLE = {
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
            "description": "reach alice@example.com",
        },
    }

    def test_hash_fields_preserved_after_sanitization(self):
        client = PIIShieldClient(enabled=True)
        sanitized, result = client.sanitize_json_document(self.BUNDLE, purpose="bundle")

        self.assertTrue(result.changed)
        for key in ("chain_hash", "content_hash", "root_hash", "signature_value",
                    "public_key_id", "previous_hash", "final_hash"):
            self.assertEqual(sanitized[key], self.BUNDLE[key], key)
        self.assertEqual(sanitized["nested"]["inner_hash"],
                         self.BUNDLE["nested"]["inner_hash"])

        # PII outside hash fields must still be redacted -- preservation
        # must not become a hole the rest of the document leaks through.
        self.assertNotIn("alice@example.com", sanitized["message"])
        self.assertNotIn("alice@example.com", sanitized["nested"]["description"])

    def test_hash_fields_never_reach_the_engine(self):
        """Was 'not sent to remote'. The trust boundary moved from the
        network to the engine call, but it is the same boundary: hash values
        must be stripped BEFORE the text is handed over, not merely restored
        afterwards, because whatever crosses that seam is what gets logged,
        counted, and (in the old world) exfiltrated."""
        seen = {}
        client = PIIShieldClient(enabled=True)
        real_redact = client._redact

        def capture(text):
            seen["text"] = text
            return real_redact(text)

        client._redact = capture
        sanitized, _ = client.sanitize_json_document(
            {"chain_hash": "sha256:aabbccdd" + "ee" * 28, "message": "hello world"},
            purpose="bundle",
        )

        self.assertNotIn("aabbccdd", seen["text"])
        self.assertEqual(sanitized["chain_hash"], "sha256:aabbccdd" + "ee" * 28)


if __name__ == "__main__":
    unittest.main()
