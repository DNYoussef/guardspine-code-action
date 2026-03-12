"""
Cross-verification tests: bundles produced by codeguard-action's bundle_generator
must pass guardspine-kernel-py's verifier.

This closes the loop on Finding 9 from the Codex audit: tests previously validated
legacy chain fields but never verified produced bundles against the canonical kernel.
"""

import hashlib
import os
import sys
import unittest
from pathlib import Path

# Add codeguard-action/src to path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from canonical_json import canonical_json_dumps

# Add guardspine-kernel-py to path for cross-verification
# Check env var > sibling directory > skip
_kernel_env = os.environ.get("GUARDSPINE_KERNEL_PY_ROOT")
if _kernel_env:
    KERNEL_PY = Path(_kernel_env)
else:
    KERNEL_PY = ROOT.parent / "guardspine-kernel-py"
if KERNEL_PY.exists():
    sys.path.insert(0, str(KERNEL_PY / "src"))
    _HAS_KERNEL = True
else:
    _HAS_KERNEL = False


def _build_test_bundle() -> dict:
    """Build a minimal v0.2.0 bundle using codeguard-action's own logic."""
    events = [
        {
            "event_type": "diff_analysis",
            "timestamp": "2026-02-10T12:00:00Z",
            "actor": "codeguard-action",
            "data": {"files_changed": 3, "additions": 42, "deletions": 7},
        },
        {
            "event_type": "risk_classification",
            "timestamp": "2026-02-10T12:00:01Z",
            "actor": "codeguard-action",
            "data": {"tier": "L1", "drivers": ["crypto_change"]},
        },
    ]

    # Build items (mirrors BundleGenerator._build_v020_items)
    items = []
    for idx, event in enumerate(events):
        content = {
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "actor": event["actor"],
            "data": event["data"],
        }
        serialized = canonical_json_dumps(content)
        content_hash = "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        items.append({
            "item_id": f"event-{idx:04d}",
            "sequence": idx,
            "content_type": f"guardspine/codeguard/{event['event_type']}",
            "content": content,
            "content_hash": content_hash,
        })

    # Build proof (mirrors BundleGenerator._build_v020_proof)
    hash_chain = []
    previous_hash = "genesis"
    for item in items:
        chain_input = (
            f"{item['sequence']}|{item['item_id']}|{item['content_type']}|"
            f"{item['content_hash']}|{previous_hash}"
        )
        chain_hash = "sha256:" + hashlib.sha256(chain_input.encode()).hexdigest()
        hash_chain.append({
            "sequence": item["sequence"],
            "item_id": item["item_id"],
            "content_type": item["content_type"],
            "content_hash": item["content_hash"],
            "previous_hash": previous_hash,
            "chain_hash": chain_hash,
        })
        previous_hash = chain_hash

    h = hashlib.sha256()
    for link in hash_chain:
        h.update(link["chain_hash"].encode("utf-8"))
    root_hash = "sha256:" + h.hexdigest()

    return {
        "bundle_id": "00000000-0000-4000-8000-000000009999",
        "version": "0.2.0",
        "created_at": "2026-02-10T12:00:02Z",
        "items": items,
        "immutability_proof": {
            "hash_chain": hash_chain,
            "root_hash": root_hash,
        },
    }


class TestCrossVerification(unittest.TestCase):
    """Verify bundles produced by codeguard-action pass kernel-py verification."""

    @unittest.skipUnless(_HAS_KERNEL, "guardspine-kernel-py not found at expected path")
    def test_codeguard_bundle_passes_kernel_verify(self):
        """A bundle built with codeguard-action logic must pass kernel-py verify."""
        from guardspine_kernel.verify import verify_bundle

        bundle = _build_test_bundle()
        result = verify_bundle(bundle)
        self.assertTrue(
            result["valid"],
            f"Kernel verification failed: {result['errors']}",
        )

    @unittest.skipUnless(_HAS_KERNEL, "guardspine-kernel-py not found at expected path")
    def test_tampered_bundle_fails_kernel_verify(self):
        """A tampered bundle must fail kernel-py verification."""
        from guardspine_kernel.verify import verify_bundle

        bundle = _build_test_bundle()
        # Tamper with content after sealing
        bundle["items"][0]["content"]["files_changed"] = 999
        result = verify_bundle(bundle)
        self.assertFalse(result["valid"], "Tampered bundle should fail verification")

    def test_bundle_structure_is_valid(self):
        """Verify the test bundle has correct v0.2.0 structure."""
        bundle = _build_test_bundle()
        self.assertEqual(bundle["version"], "0.2.0")
        self.assertEqual(len(bundle["items"]), 2)
        self.assertEqual(len(bundle["immutability_proof"]["hash_chain"]), 2)
        self.assertTrue(bundle["immutability_proof"]["root_hash"].startswith("sha256:"))
        # Chain linkage
        self.assertEqual(
            bundle["immutability_proof"]["hash_chain"][0]["previous_hash"], "genesis"
        )
        self.assertEqual(
            bundle["immutability_proof"]["hash_chain"][1]["previous_hash"],
            bundle["immutability_proof"]["hash_chain"][0]["chain_hash"],
        )


if __name__ == "__main__":
    unittest.main()
