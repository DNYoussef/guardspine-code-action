#!/usr/bin/env python3
"""
Train the GuardSpine CodeGuard confidence calibrator from eval corpora.

Defaults:
  - datasets: hand-crafted + real-cve
  - rows output: eval/results/calibration-<datasets>-<timestamp>.jsonl
  - artifact output: .guardspine/calibration/codeguard-confidence-v1.json

This uses the existing eval harness, so AI-backed review rows require an
OpenRouter key via `OPENROUTER_API_KEY` or `eval/.codeguard/.secrets.toml`.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_EVAL = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_EVAL))

from run_eval import (  # noqa: E402
    DATASETS,
    _preflight_api_key,
    build_calibration_rows,
    collect_samples,
    load_api_key,
    make_analyzer,
    run_sample,
    write_calibration_rows,
)
from src.confidence_calibrator import build_artifact, save_artifact  # noqa: E402
from src.decision_engine import DecisionEngine  # noqa: E402
from src.risk_classifier import RiskClassifier  # noqa: E402


DEFAULT_DATASETS = ("hand-crafted", "real-cve")
DEFAULT_ARTIFACT = Path(".guardspine") / "calibration" / "codeguard-confidence-v1.json"


def normalize_datasets(values: list[str]) -> list[str]:
    """Normalize, validate, and deduplicate dataset names."""

    normalized: list[str] = []
    for raw in values:
        dataset = (raw or "").strip().lower()
        if not dataset:
            continue
        if dataset == "all" and len(values) > 1:
            raise SystemExit("Use either --datasets all or explicit dataset names, not both")
        if dataset != "all" and dataset not in DATASETS:
            available = ", ".join(sorted(DATASETS))
            raise SystemExit(f"Unknown dataset: {raw}. Available: {available}, all")
        if dataset not in normalized:
            normalized.append(dataset)

    if not normalized:
        raise SystemExit("No datasets selected")
    return normalized


def resolve_repo_path(value: str | Path) -> Path:
    """Resolve a path relative to the repo root."""

    path = Path(value)
    return path if path.is_absolute() else (_ROOT / path)


def default_rows_output(datasets: list[str]) -> Path:
    """Build the default merged JSONL path under eval/results/."""

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    slug = "-".join(datasets).replace("/", "-")
    return _EVAL / "results" / f"calibration-{slug}-{stamp}.jsonl"


def default_source_label(datasets: list[str], tier: str) -> str:
    """Build a compact provenance string for artifact metadata."""

    return f"eval-corpora:{'+'.join(datasets)}:{tier.lower()}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train GuardSpine CodeGuard confidence calibrator from eval corpora"
    )
    parser.add_argument(
        "--datasets",
        nargs="+",
        default=list(DEFAULT_DATASETS),
        help="Datasets to include (default: hand-crafted real-cve)",
    )
    parser.add_argument(
        "--tier",
        choices=["auto", "L0", "L1", "L2", "L3"],
        default="auto",
        help="Tier mode for eval runs (default: auto)",
    )
    parser.add_argument(
        "--deliberate",
        action="store_true",
        help="Enable multi-round deliberation during eval runs",
    )
    parser.add_argument(
        "--max-samples-per-dataset",
        type=int,
        default=None,
        help="Optional cap for smoke runs and iteration",
    )
    parser.add_argument(
        "--rows-output",
        default=None,
        help="Optional merged JSONL output path (default: eval/results/calibration-...jsonl)",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_ARTIFACT),
        help="Calibrator artifact output path (default: .guardspine/calibration/codeguard-confidence-v1.json)",
    )
    parser.add_argument(
        "--source",
        default=None,
        help="Optional artifact provenance label",
    )
    parser.add_argument("--epochs", type=int, default=600, help="Batch GD epochs")
    parser.add_argument("--learning-rate", type=float, default=0.2, help="Batch GD learning rate")
    parser.add_argument("--l2", type=float, default=0.02, help="L2 regularization strength")
    parser.add_argument(
        "--allow-consensus-only",
        action="store_true",
        help="Allow training when no per-review rows are produced",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    datasets = normalize_datasets(args.datasets)
    forced_tier = None if args.tier == "auto" else args.tier
    rows_output = resolve_repo_path(args.rows_output) if args.rows_output else default_rows_output(datasets)
    artifact_output = resolve_repo_path(args.output)
    source_label = args.source or default_source_label(datasets, args.tier)

    print("GuardSpine CodeGuard Confidence Calibrator")
    print("=" * 60)
    print(f"Datasets: {', '.join(datasets)}")
    print(f"Tier: {args.tier}")
    print(f"Rows output: {rows_output}")
    print(f"Artifact output: {artifact_output}")

    api_key = load_api_key()
    if args.tier != "L0" and not api_key:
        raise SystemExit(
            "No OpenRouter key found. Set OPENROUTER_API_KEY or eval/.codeguard/.secrets.toml "
            "to generate AI-backed review rows."
        )
    if not _preflight_api_key(api_key, forced_tier):
        raise SystemExit(1)

    analyzer = make_analyzer(api_key, forced_tier)
    classifier = RiskClassifier(rubric="default")
    engine = DecisionEngine(policy="standard")
    samples_dir = _EVAL / "samples"

    rows: list[dict] = []
    sample_count = 0
    result_count = 0
    review_rows = 0
    consensus_rows = 0
    failed_samples = 0

    for dataset in datasets:
        sample_pairs = collect_samples(samples_dir, dataset, None)
        if args.max_samples_per_dataset is not None:
            sample_pairs = sample_pairs[: args.max_samples_per_dataset]
        print(f"\n[{dataset}] samples={len(sample_pairs)}")

        for path, dataset_name in sample_pairs:
            result, analysis = run_sample(
                path,
                dataset_name,
                analyzer,
                classifier,
                engine,
                forced_tier=forced_tier,
                deliberate=args.deliberate,
            )
            sample_count += 1
            failed_samples += 1 if result.errors else 0
            dataset_rows = build_calibration_rows(result, analysis)
            rows.extend(dataset_rows)
            review_rows += sum(1 for row in dataset_rows if row.get("kind") == "review")
            consensus_rows += sum(1 for row in dataset_rows if row.get("kind") == "consensus")
            result_count += 1

    if not rows:
        raise SystemExit("No calibration rows were produced")
    if review_rows == 0 and not args.allow_consensus_only:
        raise SystemExit(
            "No per-review calibration rows were produced "
            f"(samples={sample_count}, consensus_rows={consensus_rows}, samples_with_errors={failed_samples}). "
            "The eval harness likely ran without usable AI review. Provide an OpenRouter key, use an AI-enabled tier, "
            "or rerun with --allow-consensus-only."
        )

    write_calibration_rows(rows, rows_output)
    artifact = build_artifact(
        rows,
        source=source_label,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        l2=args.l2,
    )
    save_artifact(artifact, artifact_output)

    print("\nTraining summary")
    print("=" * 60)
    print(f"Samples processed: {sample_count}")
    print(f"Eval results: {result_count}")
    print(f"Samples with errors: {failed_samples}")
    print(f"Consensus rows: {consensus_rows}")
    print(f"Review rows: {review_rows}")
    print(f"Artifact: {artifact_output}")
    for kind, model in sorted((artifact.get('models') or {}).items()):
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
