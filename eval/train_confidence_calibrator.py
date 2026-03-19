#!/usr/bin/env python3
"""
Train a lean black-box confidence calibrator from eval JSONL rows.

Example:
    python eval/train_confidence_calibrator.py \
        --input eval/results/calibration-real-cve.jsonl \
        --output .guardspine/calibration/codeguard-confidence-v1.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from src.confidence_calibrator import build_artifact, save_artifact


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train GuardSpine CodeGuard confidence calibrator")
    parser.add_argument("--input", required=True, help="JSONL file produced by eval/run_eval.py --emit-calibration-jsonl")
    parser.add_argument("--output", required=True, help="Output JSON artifact path")
    parser.add_argument("--source", default="eval", help="Metadata label for artifact provenance")
    parser.add_argument("--epochs", type=int, default=600, help="Batch GD epochs")
    parser.add_argument("--learning-rate", type=float, default=0.2, help="Batch GD learning rate")
    parser.add_argument("--l2", type=float, default=0.02, help="L2 regularization strength")
    return parser.parse_args()


def load_rows(path: str | Path) -> list[dict]:
    rows = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def main() -> int:
    args = parse_args()
    rows = load_rows(args.input)
    if not rows:
        raise SystemExit("No calibration rows found")

    artifact = build_artifact(
        rows,
        source=args.source,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        l2=args.l2,
    )
    save_artifact(artifact, args.output)

    print(f"Trained calibrator artifact: {args.output}")
    for kind, model in sorted((artifact.get("models") or {}).items()):
        metrics = model.get("metrics", {})
        print(
            f"  {kind}: rows={model.get('count', 0)} "
            f"accuracy={metrics.get('accuracy', 0):.4f} "
            f"brier={metrics.get('brier', 0):.6f} "
            f"ece={metrics.get('ece', 0):.6f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
