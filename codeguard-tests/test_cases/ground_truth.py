"""
Ground truth definitions for CodeGuard synthetic test harness.

Enums for risk levels, categories, and the TestCase dataclass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List


class RiskLevel(IntEnum):
    L0 = 0  # Trivial: whitespace, comments, formatting
    L1 = 1  # Low: benign behavior change, trivial deps
    L2 = 2  # Moderate: secrets, auth/config, prototype pollution
    L3 = 3  # High: injection, priv-esc, crypto misuse, supply-chain
    L4 = 4  # Critical: backdoor, obfuscation+egress, RCE, exfil


# Categories that CodeGuard should assign to findings.
CATEGORIES = {
    "supply_chain",
    "injection",
    "memory_safety",
    "credential_exposure",
    "prototype_pollution",
    "dependency_hijack",
    "logging_vulnerability",
    "sql_injection",
    "ci_cd_exfiltration",
    "backdoor",
    "formatting",
    "refactor",
    "trivial_dependency",
}


@dataclass(frozen=True)
class TestCase:
    id: str
    name: str
    description: str
    real_incident: str
    real_project: str
    diff_content: str
    files_changed: List[str]
    expected_risk_level: int  # 0-4
    expected_signals: List[str]
    expected_categories: List[str]
    rationale: str
