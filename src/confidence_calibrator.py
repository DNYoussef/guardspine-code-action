"""
Lean black-box confidence calibration for GuardSpine CodeGuard.

This module intentionally avoids heavyweight ML dependencies. It provides:
  - feature extraction from CodeGuard review/consensus outputs
  - simple logistic-regression training with batch gradient descent
  - calibration metrics (Brier score, ECE)
  - runtime annotation of analysis payloads with calibrated confidence
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import pstdev
from typing import Any


ARTIFACT_TYPE = "guardspine.codeguard.confidence_calibrator"
ARTIFACT_VERSION = "1.0"
FEATURE_VERSION = "v1"
MODEL_KINDS = ("review", "consensus")


@dataclass
class CalibrationModel:
    """A fitted logistic-regression calibrator."""

    kind: str
    feature_names: list[str]
    bias: float
    weights: dict[str, float]
    means: dict[str, float]
    stds: dict[str, float]
    metrics: dict[str, float]
    count: int


def _clip01(value: Any, default: float = 0.0) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = default
    return max(0.0, min(1.0, numeric))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _log1p_int(value: Any) -> float:
    numeric = max(0.0, _safe_float(value, 0.0))
    return math.log1p(numeric)


def _family_flags(model_name: str) -> dict[str, float]:
    model = (model_name or "").lower()
    return {
        "family_claude": 1.0 if "claude" in model else 0.0,
        "family_gpt": 1.0 if ("gpt" in model or model.startswith("o1")) else 0.0,
        "family_gemini": 1.0 if "gemini" in model else 0.0,
        "family_llama": 1.0 if "llama" in model else 0.0,
        "family_mistral": 1.0 if "mistral" in model else 0.0,
        "family_qwen": 1.0 if "qwen" in model else 0.0,
        "family_other": 1.0 if not any(k in model for k in ("claude", "gpt", "gemini", "llama", "mistral", "qwen")) else 0.0,
    }


def _provider_flags(provider: str) -> dict[str, float]:
    provider = (provider or "").lower()
    return {
        "provider_ollama": 1.0 if provider == "ollama" else 0.0,
        "provider_openrouter": 1.0 if provider == "openrouter" else 0.0,
        "provider_anthropic": 1.0 if provider == "anthropic" else 0.0,
        "provider_openai": 1.0 if provider == "openai" else 0.0,
        "provider_other": 1.0 if provider not in ("ollama", "openrouter", "anthropic", "openai") else 0.0,
    }


def _tier_flags(tier: str) -> dict[str, float]:
    tier = (tier or "L2").upper()
    return {f"tier_{name.lower()}": 1.0 if tier == name else 0.0 for name in ("L0", "L1", "L2", "L3", "L4")}


def _verdict_flags(verdict: str, prefix: str = "verdict") -> dict[str, float]:
    verdict = (verdict or "").lower()
    return {
        f"{prefix}_approve": 1.0 if verdict == "approve" else 0.0,
        f"{prefix}_comment": 1.0 if verdict == "comment" else 0.0,
        f"{prefix}_request_changes": 1.0 if verdict == "request_changes" else 0.0,
    }


def _count_assessments(reviews: list[dict[str, Any]]) -> dict[str, float]:
    counts = {"approve": 0.0, "comment": 0.0, "request_changes": 0.0}
    for review in reviews:
        verdict = (review.get("risk_assessment") or "").lower()
        if verdict in counts:
            counts[verdict] += 1.0
    return {
        "count_approve": counts["approve"],
        "count_comment": counts["comment"],
        "count_request_changes": counts["request_changes"],
    }


def review_correct_label(review: dict[str, Any], expected_flag: bool) -> int:
    """Binary target: was this review's flag/no-flag call correct?"""

    verdict = (review.get("risk_assessment") or "").lower()
    if verdict == "error":
        return 0
    predicted_flag = verdict != "approve"
    return 1 if predicted_flag == bool(expected_flag) else 0


def consensus_correct_label(analysis: dict[str, Any], expected_flag: bool) -> int:
    """Binary target: was the consensus flag/no-flag call correct?"""

    verdict = (analysis.get("consensus_risk") or "").lower()
    predicted_flag = verdict not in ("", "approve", "error")
    return 1 if predicted_flag == bool(expected_flag) else 0


def extract_review_features(review: dict[str, Any], analysis: dict[str, Any]) -> dict[str, float]:
    """Extract lean, numeric features for per-review correctness calibration."""

    mmr = analysis.get("multi_model_review") or {}
    consensus = mmr.get("consensus") or {}
    review_concerns = review.get("concerns") or []
    valid_reviews = [r for r in (mmr.get("reviews") or []) if not r.get("error")]
    review_confidences = [_clip01(r.get("confidence"), 0.0) for r in valid_reviews]
    combined_concerns = consensus.get("combined_concerns") or []

    features: dict[str, float] = {
        "self_reported_confidence": _clip01(review.get("confidence"), 0.0),
        "agreement_score": _clip01(analysis.get("agreement_score", 0.0), 0.0),
        "models_used": _safe_float(analysis.get("models_used", 0.0), 0.0),
        "models_failed": _safe_float(analysis.get("models_failed", 0.0), 0.0),
        "files_changed_log1p": _log1p_int(analysis.get("files_changed", 0)),
        "lines_added_log1p": _log1p_int(analysis.get("lines_added", 0)),
        "lines_removed_log1p": _log1p_int(analysis.get("lines_removed", 0)),
        "sensitive_zones_count_log1p": _log1p_int(len(analysis.get("sensitive_zones", []))),
        "review_concern_count": float(len(review_concerns)),
        "combined_concern_count": float(len(combined_concerns)),
        "review_parse_error": 1.0 if review.get("parse_error") else 0.0,
        "review_has_error": 1.0 if review.get("error") else 0.0,
        "review_matches_consensus": 1.0 if (review.get("risk_assessment") == consensus.get("consensus_risk")) else 0.0,
        "consensus_review_mean_confidence": sum(review_confidences) / len(review_confidences) if review_confidences else 0.0,
        "consensus_review_max_confidence": max(review_confidences) if review_confidences else 0.0,
        "consensus_review_min_confidence": min(review_confidences) if review_confidences else 0.0,
        "consensus_review_confidence_std": pstdev(review_confidences) if len(review_confidences) > 1 else 0.0,
    }
    features.update(_verdict_flags(review.get("risk_assessment"), prefix="verdict"))
    features.update(_verdict_flags(consensus.get("consensus_risk"), prefix="consensus"))
    features.update(_provider_flags(review.get("provider", "")))
    features.update(_family_flags(review.get("model_name", "")))
    features.update(_tier_flags(analysis.get("preliminary_tier", "L2")))
    features.update(_count_assessments(valid_reviews))
    return features


def extract_consensus_features(analysis: dict[str, Any]) -> dict[str, float]:
    """Extract lean, numeric features for consensus correctness calibration."""

    mmr = analysis.get("multi_model_review") or {}
    consensus = mmr.get("consensus") or {}
    valid_reviews = [r for r in (mmr.get("reviews") or []) if not r.get("error")]
    review_confidences = [_clip01(r.get("confidence"), 0.0) for r in valid_reviews]
    combined_concerns = consensus.get("combined_concerns") or []

    features: dict[str, float] = {
        "agreement_score": _clip01(analysis.get("agreement_score", 0.0), 0.0),
        "models_used": _safe_float(analysis.get("models_used", 0.0), 0.0),
        "models_failed": _safe_float(analysis.get("models_failed", 0.0), 0.0),
        "files_changed_log1p": _log1p_int(analysis.get("files_changed", 0)),
        "lines_added_log1p": _log1p_int(analysis.get("lines_added", 0)),
        "lines_removed_log1p": _log1p_int(analysis.get("lines_removed", 0)),
        "sensitive_zones_count_log1p": _log1p_int(len(analysis.get("sensitive_zones", []))),
        "combined_concern_count": float(len(combined_concerns)),
        "review_count": float(len(valid_reviews)),
        "deliberation_rounds": _safe_float(mmr.get("deliberation_rounds", 0), 0.0),
        "early_exit": 1.0 if mmr.get("early_exit") else 0.0,
        "mean_self_reported_confidence": sum(review_confidences) / len(review_confidences) if review_confidences else 0.0,
        "max_self_reported_confidence": max(review_confidences) if review_confidences else 0.0,
        "min_self_reported_confidence": min(review_confidences) if review_confidences else 0.0,
        "std_self_reported_confidence": pstdev(review_confidences) if len(review_confidences) > 1 else 0.0,
    }
    features.update(_verdict_flags(analysis.get("consensus_risk"), prefix="consensus"))
    features.update(_tier_flags(analysis.get("preliminary_tier", "L2")))
    features.update(_count_assessments(valid_reviews))
    return features


def make_review_training_row(
    review: dict[str, Any],
    analysis: dict[str, Any],
    expected_flag: bool,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Create a serializable per-review training example."""

    return {
        "kind": "review",
        "feature_version": FEATURE_VERSION,
        "correct": review_correct_label(review, expected_flag),
        "expected_flag": bool(expected_flag),
        "predicted_flag": (review.get("risk_assessment") or "").lower() != "approve",
        "verdict": review.get("risk_assessment", ""),
        "features": extract_review_features(review, analysis),
        "metadata": {
            **metadata,
            "provider": review.get("provider", ""),
            "model_name": review.get("model_name", ""),
            "model_id": review.get("model_id", review.get("model_name", "")),
        },
    }


def make_consensus_training_row(
    analysis: dict[str, Any],
    expected_flag: bool,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Create a serializable consensus-level training example."""

    return {
        "kind": "consensus",
        "feature_version": FEATURE_VERSION,
        "correct": consensus_correct_label(analysis, expected_flag),
        "expected_flag": bool(expected_flag),
        "predicted_flag": (analysis.get("consensus_risk") or "").lower() not in ("", "approve", "error"),
        "verdict": analysis.get("consensus_risk", ""),
        "features": extract_consensus_features(analysis),
        "metadata": metadata,
    }


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def _normalize_rows(rows: list[dict[str, float]], feature_names: list[str]) -> tuple[list[dict[str, float]], dict[str, float], dict[str, float]]:
    means: dict[str, float] = {}
    stds: dict[str, float] = {}
    normalized: list[dict[str, float]] = []

    for name in feature_names:
        values = [row.get(name, 0.0) for row in rows]
        mean = sum(values) / len(values) if values else 0.0
        variance = sum((value - mean) ** 2 for value in values) / len(values) if values else 0.0
        std = math.sqrt(variance) if variance > 1e-12 else 1.0
        means[name] = mean
        stds[name] = std

    for row in rows:
        normalized.append({
            name: (row.get(name, 0.0) - means[name]) / stds[name]
            for name in feature_names
        })

    return normalized, means, stds


def _predict_with_model(features: dict[str, float], model: CalibrationModel | dict[str, Any]) -> float:
    if isinstance(model, dict):
        bias = _safe_float(model.get("bias", 0.0), 0.0)
        weights = {str(k): _safe_float(v, 0.0) for k, v in (model.get("weights") or {}).items()}
        means = {str(k): _safe_float(v, 0.0) for k, v in (model.get("means") or {}).items()}
        stds = {
            str(k): (_safe_float(v, 1.0) or 1.0)
            for k, v in (model.get("stds") or {}).items()
        }
        feature_names = list(model.get("feature_names") or weights.keys())
    else:
        bias = model.bias
        weights = model.weights
        means = model.means
        stds = model.stds
        feature_names = model.feature_names

    total = bias
    for name in feature_names:
        raw = _safe_float(features.get(name, 0.0), 0.0)
        total += ((raw - means.get(name, 0.0)) / (stds.get(name, 1.0) or 1.0)) * weights.get(name, 0.0)
    return _sigmoid(total)


def _compute_metrics(labels: list[int], probabilities: list[float], bins: int = 10) -> dict[str, float]:
    if not labels:
        return {"accuracy": 0.0, "brier": 0.0, "ece": 0.0}

    accuracy = sum((prob >= 0.5) == bool(label) for label, prob in zip(labels, probabilities)) / len(labels)
    brier = sum((prob - label) ** 2 for label, prob in zip(labels, probabilities)) / len(labels)

    ece = 0.0
    for idx in range(bins):
        lower = idx / bins
        upper = (idx + 1) / bins
        bucket = [
            (label, prob)
            for label, prob in zip(labels, probabilities)
            if (lower <= prob < upper) or (idx == bins - 1 and lower <= prob <= upper)
        ]
        if not bucket:
            continue
        # Calibration compares predicted probability to empirical frequency.
        bucket_acc = sum(label for label, _ in bucket) / len(bucket)
        bucket_conf = sum(prob for _, prob in bucket) / len(bucket)
        ece += abs(bucket_acc - bucket_conf) * (len(bucket) / len(labels))

    return {
        "accuracy": round(accuracy, 4),
        "brier": round(brier, 6),
        "ece": round(ece, 6),
    }


def fit_logistic_calibrator(
    rows: list[dict[str, Any]],
    kind: str,
    *,
    epochs: int = 600,
    learning_rate: float = 0.2,
    l2: float = 0.02,
) -> CalibrationModel:
    """Fit a logistic-regression calibrator from JSONL-style rows."""

    if kind not in MODEL_KINDS:
        raise ValueError(f"Unknown calibrator kind: {kind}")

    filtered = [row for row in rows if row.get("kind") == kind]
    if not filtered:
        raise ValueError(f"No rows found for calibrator kind: {kind}")

    feature_names = sorted({
        name
        for row in filtered
        for name in (row.get("features") or {}).keys()
    })
    if not feature_names:
        raise ValueError(f"No features found for calibrator kind: {kind}")

    raw_rows = [{name: _safe_float((row.get("features") or {}).get(name, 0.0), 0.0) for name in feature_names} for row in filtered]
    labels = [1 if row.get("correct") else 0 for row in filtered]
    normalized_rows, means, stds = _normalize_rows(raw_rows, feature_names)

    weights = {name: 0.0 for name in feature_names}
    bias = 0.0

    for _ in range(epochs):
        grad_bias = 0.0
        grad_weights = {name: 0.0 for name in feature_names}

        for row, label in zip(normalized_rows, labels):
            linear = bias + sum(row[name] * weights[name] for name in feature_names)
            prediction = _sigmoid(linear)
            error = prediction - label
            grad_bias += error
            for name in feature_names:
                grad_weights[name] += error * row[name]

        count = float(len(labels))
        bias -= learning_rate * (grad_bias / count)
        for name in feature_names:
            grad = (grad_weights[name] / count) + l2 * weights[name]
            weights[name] -= learning_rate * grad

    probabilities = [
        _predict_with_model(raw_row, {
            "feature_names": feature_names,
            "bias": bias,
            "weights": weights,
            "means": means,
            "stds": stds,
        })
        for raw_row in raw_rows
    ]
    metrics = _compute_metrics(labels, probabilities)

    return CalibrationModel(
        kind=kind,
        feature_names=feature_names,
        bias=bias,
        weights=weights,
        means=means,
        stds=stds,
        metrics=metrics,
        count=len(filtered),
    )


def build_artifact(
    rows: list[dict[str, Any]],
    *,
    source: str = "eval",
    epochs: int = 600,
    learning_rate: float = 0.2,
    l2: float = 0.02,
) -> dict[str, Any]:
    """Train all available calibrators and return a serializable artifact."""

    artifact: dict[str, Any] = {
        "artifact_type": ARTIFACT_TYPE,
        "artifact_version": ARTIFACT_VERSION,
        "feature_version": FEATURE_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "models": {},
        "training_rows": len(rows),
    }

    for kind in MODEL_KINDS:
        matching = [row for row in rows if row.get("kind") == kind]
        if not matching:
            continue
        model = fit_logistic_calibrator(
            matching,
            kind,
            epochs=epochs,
            learning_rate=learning_rate,
            l2=l2,
        )
        artifact["models"][kind] = {
            "kind": model.kind,
            "feature_names": model.feature_names,
            "bias": model.bias,
            "weights": model.weights,
            "means": model.means,
            "stds": model.stds,
            "metrics": model.metrics,
            "count": model.count,
        }

    if not artifact["models"]:
        raise ValueError("No calibrator models were trained")

    return artifact


def load_artifact(path: str | Path) -> dict[str, Any]:
    """Load a calibrator artifact from JSON."""

    artifact_path = Path(path)
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    if artifact.get("artifact_type") != ARTIFACT_TYPE:
        raise ValueError(f"Unsupported calibrator artifact: {artifact.get('artifact_type')}")
    return artifact


def save_artifact(artifact: dict[str, Any], path: str | Path) -> Path:
    """Write a calibrator artifact to disk."""

    artifact_path = Path(path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
    return artifact_path


def annotate_analysis_with_calibration(
    analysis: dict[str, Any],
    artifact: dict[str, Any],
) -> dict[str, Any]:
    """Annotate an analysis payload with calibrated confidence data."""

    mmr = analysis.get("multi_model_review") or {}
    reviews = mmr.get("reviews") or []
    models = artifact.get("models") or {}

    review_probs: list[float] = []
    if "review" in models:
        for review in reviews:
            if review.get("error"):
                continue
            review["confidence_self_reported"] = _clip01(review.get("confidence"), 0.0)
            calibrated = _predict_with_model(extract_review_features(review, analysis), models["review"])
            review["calibrated_confidence"] = round(calibrated, 4)
            review["confidence_source"] = "black_box_calibrator_v1"
            review_probs.append(calibrated)

    calibrated_consensus = None
    if "consensus" in models:
        calibrated_consensus = _predict_with_model(extract_consensus_features(analysis), models["consensus"])

    calibration_summary = {
        "enabled": True,
        "source": "black_box_calibrator_v1",
        "artifact_version": artifact.get("artifact_version", ARTIFACT_VERSION),
        "feature_version": artifact.get("feature_version", FEATURE_VERSION),
        "trained_at": artifact.get("trained_at", ""),
        "models": {
            kind: {
                "count": model.get("count", 0),
                "metrics": model.get("metrics", {}),
            }
            for kind, model in models.items()
        },
        "calibrated_verdict_p_correct": round(calibrated_consensus, 4) if calibrated_consensus is not None else None,
        "review_p_correct_mean": round(sum(review_probs) / len(review_probs), 4) if review_probs else None,
        "reviews_calibrated": len(review_probs),
    }

    analysis["confidence_calibration"] = calibration_summary
    mmr["confidence_calibration"] = calibration_summary
    analysis["multi_model_review"] = mmr
    return calibration_summary
