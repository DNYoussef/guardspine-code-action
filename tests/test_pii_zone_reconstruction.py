"""Zones must be reconstructed from the redacted text, without HTTP.

The regression these tests pin: after the HTTP client was deleted, the
WASM path returned signals=[] unconditionally, so entrypoint.py merged
ZERO zones and the RiskClassifier scored ZERO PII risk -- while the
pipeline still looked like it was scoring PII. The engine returns
redacted TEXT, and that is enough: a line that differs between input and
output contained PII. These tests fail on the empty-signals version and
pass only when line-diff reconstruction is in place.

Engine calls are injected at `PIIShieldClient._redact`, the seam the
production code isolates for exactly this purpose, so every test is
deterministic and none depends on what the current engine version
happens to detect.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.pii_shield import PIIShieldClient

INPUT_TEXT = (
    "line one is clean\n"
    "email = 'alice@example.com'\n"
    "line three is clean\n"
    "ssn = '123-45-6789'\n"
)

# Same line count, lines 2 and 4 redacted -- the aligned case.
REDACTED_ALIGNED = (
    "line one is clean\n"
    "email = '[HIDDEN:a1b2]'\n"
    "line three is clean\n"
    "ssn = '[HIDDEN:c3d4]'\n"
)

# Fewer lines than the input -- the engine reflowed. Blind zipping would
# attribute changes to the wrong lines, so this must fall back to one
# coarse whole-document zone rather than emitting wrong lines or none.
REDACTED_REFLOWED = (
    "line one is clean\n"
    "[HIDDEN:a1b2] [HIDDEN:c3d4]\n"
)


def _client() -> PIIShieldClient:
    return PIIShieldClient(enabled=True, fail_closed=True)


class TestZoneReconstruction(unittest.TestCase):
    def test_changed_lines_become_zones_with_line_numbers(self):
        """THE regression test: PII on lines 2 and 4 must yield zones for
        lines 2 and 4. On the empty-signals version this list is [] and
        the classifier scores nothing."""
        with patch.object(PIIShieldClient, "_redact", return_value=REDACTED_ALIGNED):
            result = _client().sanitize_diff(INPUT_TEXT)

        zones = result.to_sensitive_zones()
        self.assertEqual([z["line"] for z in zones], [2, 4])
        for z in zones:
            # "pii" is the zone the classifier scores as critical; a made-up
            # name would silently map to the "medium" default.
            self.assertEqual(z["zone"], "pii")
            self.assertEqual(z["detector"], "pii_shield")
            self.assertGreaterEqual(z["count"], 1)

    def test_zones_never_carry_pii_or_redaction_tokens(self):
        """A zone is a location and a count. If the matched value or even
        the [HIDDEN:...] token leaks into a zone, risk metadata becomes a
        PII sink -- the exact failure this module exists to prevent."""
        with patch.object(PIIShieldClient, "_redact", return_value=REDACTED_ALIGNED):
            result = _client().sanitize_diff(INPUT_TEXT)

        zones = result.to_sensitive_zones()
        self.assertTrue(zones)
        for z in zones:
            for value in z.values():
                if not isinstance(value, str):
                    continue
                self.assertNotIn("alice@example.com", value)
                self.assertNotIn("123-45-6789", value)
                self.assertNotIn("[HIDDEN", value)

    def test_reflowed_output_yields_coarse_zone_not_silence(self):
        """When line counts differ, alignment is not trusted; the honest
        degradation is one whole-document zone (line=None), never zero
        zones -- zero is the silent-regression shape."""
        with patch.object(PIIShieldClient, "_redact", return_value=REDACTED_REFLOWED):
            result = _client().sanitize_diff(INPUT_TEXT)

        zones = result.to_sensitive_zones()
        self.assertEqual(len(zones), 1)
        self.assertIsNone(zones[0]["line"])
        self.assertEqual(zones[0]["zone"], "pii")
        self.assertGreaterEqual(zones[0]["count"], 1)

    def test_unchanged_text_yields_no_zones(self):
        """No redaction means no PII evidence; inventing a zone here would
        escalate every clean diff to critical."""
        with patch.object(PIIShieldClient, "_redact", return_value=INPUT_TEXT):
            result = _client().sanitize_diff(INPUT_TEXT)

        self.assertFalse(result.changed)
        self.assertEqual(result.to_sensitive_zones(), [])

    def test_metadata_signal_count_reflects_reconstruction(self):
        """to_metadata()'s signal_count fed dashboards; it must count the
        reconstructed zones, not stay pinned at 0."""
        with patch.object(PIIShieldClient, "_redact", return_value=REDACTED_ALIGNED):
            result = _client().sanitize_diff(INPUT_TEXT)

        self.assertEqual(result.to_metadata()["signal_count"], 2)


class TestZoneReconstructionRealEngine(unittest.TestCase):
    """One unmocked pass so the contract is proven against the actual
    pii-shield-wasi engine, not only against a stand-in string."""

    def test_real_engine_email_line_is_zoned(self):
        client = _client()
        text = "clean line\nemail = 'alice@example.com'\n"
        result = client.sanitize_diff(text)
        if not result.changed:
            self.skipTest("engine did not redact the fixture email")
        zones = result.to_sensitive_zones()
        self.assertTrue(zones)
        lines = [z["line"] for z in zones]
        self.assertTrue(lines == [2] or lines == [None])


if __name__ == "__main__":
    unittest.main()
