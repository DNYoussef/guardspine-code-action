"""Tests for the eval/train_confidence_from_corpora.py helper."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from train_confidence_from_corpora import (  # noqa: E402
    default_rows_output,
    default_source_label,
    normalize_datasets,
    resolve_repo_path,
)


class TestTrainConfidenceFromCorpora(unittest.TestCase):
    def test_normalize_datasets_deduplicates_and_preserves_order(self):
        self.assertEqual(
            normalize_datasets(["hand-crafted", "real-cve", "hand-crafted"]),
            ["hand-crafted", "real-cve"],
        )

    def test_normalize_datasets_rejects_all_plus_explicit(self):
        with self.assertRaises(SystemExit):
            normalize_datasets(["all", "hand-crafted"])

    def test_default_rows_output_uses_eval_results(self):
        path = default_rows_output(["hand-crafted", "real-cve"])
        self.assertEqual(path.parent.name, "results")
        self.assertEqual(path.parent.parent.name, "eval")
        self.assertTrue(path.name.startswith("calibration-hand-crafted-real-cve-"))
        self.assertTrue(path.name.endswith(".jsonl"))

    def test_default_source_label_includes_datasets_and_tier(self):
        self.assertEqual(
            default_source_label(["hand-crafted", "real-cve"], "auto"),
            "eval-corpora:hand-crafted+real-cve:auto",
        )

    def test_resolve_repo_path_maps_relative_to_repo_root(self):
        resolved = resolve_repo_path(".guardspine/calibration/codeguard-confidence-v1.json")
        self.assertEqual(resolved, ROOT / ".guardspine" / "calibration" / "codeguard-confidence-v1.json")


if __name__ == "__main__":
    unittest.main()
