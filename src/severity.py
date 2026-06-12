"""Canonical severity handling for CodeGuard findings and policies."""

from __future__ import annotations

from typing import Any

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
FAIL_CLOSED_SEVERITY = "critical"

_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def normalize_severity(value: Any, *, unknown: str = FAIL_CLOSED_SEVERITY) -> str:
    """Normalize finding severity, failing closed on unknown values."""
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _SEVERITY_RANK:
            return normalized
    return unknown


def validate_severity(value: Any, *, context: str = "severity") -> str:
    """Normalize a configured severity or raise on invalid policy input."""
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _SEVERITY_RANK:
            return normalized
    raise ValueError(
        f"{context} must be one of {', '.join(VALID_SEVERITIES)}; got {value!r}"
    )


def severity_rank(value: Any) -> int:
    """Return a rank for sorting/scoring, fail-closed for malformed values."""
    return _SEVERITY_RANK[normalize_severity(value)]
