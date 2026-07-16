"""
Tests for canonical JSON normalization used by bundle hashing/signing.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from canonical_json import canonical_json_dumps


class TestCanonicalJson(unittest.TestCase):
    def test_equivalent_payloads_produce_identical_canonical_json(self):
        """Keys sort + sets sort, but strings pass through as-is (no NFC)."""
        payload_a = {
            "z": {"b": 2, "a": 1},
            "tags": {"gamma", "alpha", "beta"},
            "label": "hello",
        }
        payload_b = {
            "label": "hello",
            "tags": {"beta", "gamma", "alpha"},
            "z": {"a": 1, "b": 2},
        }
        self.assertEqual(canonical_json_dumps(payload_a), canonical_json_dumps(payload_b))

    def test_nfd_and_nfc_are_not_equivalent(self):
        """Canonical JSON must NOT normalize Unicode to match kernel behavior.

        NFD 'Cafe\\u0301' and NFC 'Caf\\xe9' are visually identical but
        produce different bytes. The kernel (canonical.ts) does not normalize,
        so we must not either -- otherwise bundles sealed here would fail
        kernel verification for non-NFC input.
        """
        nfd = canonical_json_dumps({"label": "Cafe\u0301"})
        nfc = canonical_json_dumps({"label": "Caf\u00e9"})
        self.assertNotEqual(nfd, nfc)

    def test_non_finite_float_is_rejected(self):
        with self.assertRaises(ValueError):
            canonical_json_dumps({"score": float("nan")})

    def test_matches_guardspine_kernel_for_floats(self):
        """R0.6 float contract: canonical_json_dumps MUST be byte-identical to
        the guardspine-kernel RFC 8785 canonicalizer the backend re-verifies
        with. Python's json.dumps renders a float 1.0 as "1.0" while RFC 8785
        renders "1", so a revert to json.dumps here would leave local signing
        tests green but make the backend reject any float-bearing (AI-scored)
        bundle at import (422). Guard that exact regression."""
        from guardspine_kernel.canonical import canonical_json as kernel_canonical_json

        for obj in (
            {"score": 1.0, "z": 0.0, "half": 1.5},
            {"nested": {"weights": [1.0, 2.5, 0.0]}},
            {"a": 1, "b": "x", "c": [1, 2]},  # no-float case stays identical too
        ):
            self.assertEqual(
                canonical_json_dumps(obj),
                kernel_canonical_json(obj),
                f"canonical divergence from kernel for {obj!r}",
            )


if __name__ == "__main__":
    unittest.main()

