"""
Decision Engine - findings in, one decision out.

Vendored from guardspine-product (decision.engine + code_guard.audit.Finding).
Last synced: 2026-03-08. Re-sync manually when guardspine-product decision logic changes.
Kept vendored because codeguard-action runs in Docker without private pip indexes.

No abstractions. No plugin system. Just a pure function that
collapses a pile of findings into: merge, merge-with-conditions, or block.

Provable findings (deterministic detections) can hard-block.
Opinion findings (model-generated) are advisory-only.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single audit finding."""
    severity: str  # critical | high | medium | low | info
    category: str  # security | correctness | performance
    location: str | None = None  # file:line or null
    description: str = ""
    recommendation: str = ""
    provable: bool = False  # True = deterministic detection, False = model opinion


@dataclass
class DecisionPacket:
    """One PR, one decision."""
    decision: str  # "merge" | "merge-with-conditions" | "block"
    hard_blocks: list[Finding] = field(default_factory=list)
    conditions: list[Finding] = field(default_factory=list)  # max 2
    advisory: list[Finding] = field(default_factory=list)
    total_findings: int = 0
    policy_name: str = "standard"


# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------

_PROFILES_DIR = Path(__file__).parent / "decision_profiles"

_DEFAULT_POLICY = {
    "name": "standard",
    "hard_block_rules": [
        {"severity": "critical", "provable_only": True},
    ],
    "condition_rules": [
        {"severity": "critical", "provable_only": False},
        {"severity": "high", "provable_only": False},
    ],
    "max_conditions": 2,
}


def load_policy(name_or_path: str = "standard") -> dict[str, Any]:
    """Load a policy profile by name or file path."""
    path = Path(name_or_path)
    if not path.exists():
        path = _PROFILES_DIR / f"{name_or_path}.yaml"
    if not path.exists():
        return _DEFAULT_POLICY
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or _DEFAULT_POLICY


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _severity_key(f: Finding) -> int:
    return _SEVERITY_RANK.get(f.severity, 0)


def _matches_rule(finding: Finding, rule: dict[str, Any]) -> bool:
    """Check if a finding matches a policy rule."""
    if rule.get("severity") and finding.severity != rule["severity"]:
        return False
    if rule.get("provable_only") and not finding.provable:
        return False
    if rule.get("category") and finding.category != rule["category"]:
        return False
    return True


class DecisionEngine:
    """Collapse findings into one decision."""

    def __init__(self, policy: str = "standard"):
        self._policy = load_policy(policy)

    def decide(self, findings: list[Finding]) -> DecisionPacket:
        """
        findings in -> one DecisionPacket out.

        Logic:
        1. Any finding matching hard_block_rules -> BLOCK
        2. Top findings matching condition_rules (max N) -> MERGE-WITH-CONDITIONS
        3. Everything else -> MERGE (advisory findings attached for context)
        """
        hard_blocks: list[Finding] = []
        condition_candidates: list[Finding] = []
        advisory: list[Finding] = []

        block_rules = self._policy.get("hard_block_rules", [])
        cond_rules = self._policy.get("condition_rules", [])
        max_cond = self._policy.get("max_conditions", 2)

        for f in findings:
            # Check hard block rules first
            if any(_matches_rule(f, r) for r in block_rules):
                hard_blocks.append(f)
                continue

            # Check condition rules
            if any(_matches_rule(f, r) for r in cond_rules):
                condition_candidates.append(f)
                continue

            # Everything else is advisory
            advisory.append(f)

        # Sort conditions by severity descending, take top N
        condition_candidates.sort(key=_severity_key, reverse=True)
        conditions = condition_candidates[:max_cond]
        # Overflow conditions become advisory
        advisory.extend(condition_candidates[max_cond:])

        # Decide
        if hard_blocks:
            decision = "block"
        elif conditions:
            decision = "merge-with-conditions"
        else:
            decision = "merge"

        return DecisionPacket(
            decision=decision,
            hard_blocks=hard_blocks,
            conditions=conditions,
            advisory=advisory,
            total_findings=len(findings),
            policy_name=self._policy.get("name", "unknown"),
        )


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def render_decision_card(packet: DecisionPacket) -> str:
    """Render a DecisionPacket as a GitHub PR comment (markdown)."""
    icon = {"merge": ">>", "merge-with-conditions": "!!", "block": "XX"}
    label = {
        "merge": "MERGE - Safe to merge",
        "merge-with-conditions": "CONDITIONAL - Reviewer action needed",
        "block": "BLOCKED - Cannot merge",
    }

    lines = [
        f"## [{icon.get(packet.decision, '??')}] GuardSpine: {label.get(packet.decision, packet.decision)}",
        "",
        f"**Policy:** {packet.policy_name} | **Findings:** {packet.total_findings}",
        "",
    ]

    if packet.hard_blocks:
        lines.append("### Hard Blocks (provable failures)")
        lines.append("")
        for f in packet.hard_blocks:
            loc = f" (`{f.location}`)" if f.location else ""
            lines.append(f"- **{f.severity.upper()}** [{f.category}]{loc}: {f.description}")
        lines.append("")

    if packet.conditions:
        lines.append("### Reviewer Action Required (max 2)")
        lines.append("")
        for i, f in enumerate(packet.conditions, 1):
            loc = f" (`{f.location}`)" if f.location else ""
            lines.append(f"{i}. **{f.severity.upper()}** [{f.category}]{loc}: {f.description}")
            lines.append(f"   > {f.recommendation}")
        lines.append("")

    if packet.advisory:
        lines.append(f"<details><summary>Advisory ({len(packet.advisory)} items)</summary>")
        lines.append("")
        for f in packet.advisory:
            lines.append(f"- [{f.severity}] {f.description}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if not packet.hard_blocks and not packet.conditions and not packet.advisory:
        lines.append("No issues found. Clean merge.")
        lines.append("")

    lines.append("---")
    lines.append("*GuardSpine Decision Engine | Removing reviewer decisions, not just effort*")

    return "\n".join(lines)
