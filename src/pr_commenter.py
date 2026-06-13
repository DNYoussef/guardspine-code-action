# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 GuardSpine, Inc.
# Licensed under the Business Source License 1.1. See LICENSE for terms.
# Change License: Apache-2.0. Change Date: see LICENSE.
"""
PR Commenter - Posts risk summaries as PR comments.
"""

from typing import Any
from github import Github
from github.Repository import Repository
from github.PullRequest import PullRequest


class PRCommenter:
    """
    Posts GuardSpine analysis summaries as PR comments.

    Creates a "Diff Postcard" summary showing:
    - Risk tier with visual indicator
    - Top risk drivers
    - Findings summary
    - Approval requirements
    """

    COMMENT_MARKER = "<!-- guardspine-codeguard -->"

    # Risk tier badges and colors
    TIER_INFO = {
        "L0": {"emoji": "white_check_mark", "label": "Trivial", "color": "brightgreen"},
        "L1": {"emoji": "large_blue_circle", "label": "Low Risk", "color": "blue"},
        "L2": {"emoji": "yellow_circle", "label": "Medium Risk", "color": "yellow"},
        "L3": {"emoji": "orange_circle", "label": "High Risk", "color": "orange"},
        "L4": {"emoji": "red_circle", "label": "Critical Risk", "color": "red"},
    }

    def __init__(self, gh: Github, repo: Repository, pr: PullRequest):
        """Initialize commenter with GitHub objects."""
        self.gh = gh
        self.repo = repo
        self.pr = pr

    def post_summary(
        self,
        risk_tier: str,
        risk_drivers: list[dict],
        findings: list[dict],
        requires_approval: bool,
        threshold: str = "L3"
    ) -> None:
        """
        Post or update the GuardSpine summary comment.

        Args:
            risk_tier: Risk classification (L0-L4)
            risk_drivers: List of risk driver dicts
            findings: List of finding dicts
            requires_approval: Whether human approval is needed
            threshold: Configured threshold for blocking
        """
        comment_body = self._build_comment(
            risk_tier=risk_tier,
            risk_drivers=risk_drivers,
            findings=findings,
            requires_approval=requires_approval,
            threshold=threshold
        )

        # Check for existing comment to update
        existing_comment = self._find_existing_comment()

        if existing_comment:
            existing_comment.edit(comment_body)
        else:
            self.pr.create_issue_comment(comment_body)

    def _find_existing_comment(self):
        """Find existing GuardSpine comment if any."""
        for comment in self.pr.get_issue_comments():
            if self.COMMENT_MARKER in comment.body:
                return comment
        return None

    # Governance language rewrites: static-analysis -> governance framing
    GOVERNANCE_REWRITES = {
        "sensitive crypto code modified": "Security-relevant diff without traceable approval artifact",
        "sensitive auth code modified": "Auth logic changed without corresponding review evidence",
        "possible null dereference": "Runtime-impacting change lacks rollback signal",
        "potential auth bug": "Privilege-sensitive path modified; reviewer signoff missing",
        "sensitive security code modified": "Security-boundary change requires governance evidence",
        "sensitive config code modified": "Infrastructure config changed without policy review",
        "sensitive database code modified": "Data-layer change without migration evidence",
        "sensitive infra code modified": "Infrastructure change without deployment review",
    }

    def _reframe_to_governance(self, message: str) -> str:
        """Reframe static-analysis language to governance language."""
        msg_lower = message.lower().strip()
        for pattern, replacement in self.GOVERNANCE_REWRITES.items():
            if pattern in msg_lower:
                return replacement
        return message

    def _build_comment(
        self,
        risk_tier: str,
        risk_drivers: list[dict],
        findings: list[dict],
        requires_approval: bool,
        threshold: str
    ) -> str:
        """Build the 5-section governance comment.

        Section A: Executive risk header
        Section B: Governance findings (max 3, governance language)
        Section C: Evidence status
        Section D: Merge posture
        Section E: Viral install CTA
        """
        tier_info = self.TIER_INFO.get(risk_tier, self.TIER_INFO["L2"])

        # Count findings by severity
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")
        total = len(findings)
        evidence_status = "Complete" if not requires_approval else "Review needed"
        policy_status = "Compliant" if risk_tier in ("L0", "L1") else "Conditions" if risk_tier in ("L2", "L3") else "Blocked"

        # === SECTION A: Executive Risk Header ===
        lines = [
            self.COMMENT_MARKER,
            "",
            f"## :{tier_info['emoji']}: GuardSpine: **{risk_tier}** ({tier_info['label']})",
            "",
            f"**Risk:** {risk_tier} | **Confidence:** High | **Evidence:** {evidence_status} | **Policy:** {policy_status}",
            "",
        ]

        # === SECTION B: Governance Findings (max 3, governance language) ===
        if findings:
            # Show max 3 top findings, reframed to governance language
            top_findings = sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.get("severity", "medium"), 3))[:3]

            lines.append("### Governance Findings")
            lines.append("")

            for i, finding in enumerate(top_findings, 1):
                file_path = finding.get("file", "unknown")
                line_num = finding.get("line")
                message = self._reframe_to_governance(finding.get("message", ""))
                location = f"`{file_path}"
                if line_num:
                    location += f":{line_num}"
                location += "`"
                lines.append(f"{i}. {location}: {message}")

            lines.append("")

            # Collapsible full list if more than 3
            if total > 3:
                lines.extend([
                    f"<details><summary>All {total} findings</summary>",
                    "",
                ])
                for finding in findings:
                    file_path = finding.get("file", "unknown")
                    line_num = finding.get("line")
                    message = self._reframe_to_governance(finding.get("message", ""))
                    severity = finding.get("severity", "medium")
                    location = f"`{file_path}"
                    if line_num:
                        location += f":{line_num}"
                    location += "`"
                    lines.append(f"- [{severity}] {location}: {message}")
                lines.extend(["", "</details>", ""])

        # === SECTION C: Evidence Status ===
        lines.extend([
            "### Evidence",
            "",
            f"- Evidence bundle: {'Generated' if total > 0 else 'N/A'} (available in workflow artifacts)",
            f"- Risk drivers: {len(risk_drivers)}",
            f"- Findings: {critical_count} critical, {high_count} high, {total - critical_count - high_count} other",
            "",
        ])

        # === SECTION D: Merge Posture ===
        if requires_approval:
            lines.extend([
                f"### :octagonal_sign: Merge blocked",
                "",
                f"Risk tier **{risk_tier}** exceeds threshold **{threshold}**. Human review required.",
                "",
            ])
        elif risk_tier in ("L2", "L3"):
            lines.extend([
                f"### :warning: Merge with conditions",
                "",
                f"Address the governance findings above before merging.",
                "",
            ])
        else:
            lines.extend([
                f"### :white_check_mark: Safe to merge",
                "",
            ])

        # === SECTION E: Viral Install CTA ===
        governance_gaps = critical_count + high_count
        lines.extend([
            "---",
            "",
            f"*This PR was analyzed by [GuardSpine CodeGuard](https://github.com/DNYoussef/codeguard-action).*",
        ])

        if governance_gaps > 0:
            lines.append(f"*Your repo has **{governance_gaps}** unresolved governance gaps.*")

        lines.extend([
            f"*Install on your repo: [`DNYoussef/codeguard-action@v1`](https://github.com/DNYoussef/codeguard-action)*",
            "",
            "*GuardSpine Decision Engine | Removing reviewer decisions, not just effort*",
        ])

        return "\n".join(lines)

    def _severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        return {
            "critical": ":red_circle:",
            "high": ":orange_circle:",
            "medium": ":yellow_circle:",
            "low": ":large_blue_circle:",
            "info": ":white_circle:",
        }.get(severity, ":white_circle:")

    def post_decision_card(self, decision_card_md: str) -> None:
        """
        Post or update the Decision Card comment.

        Args:
            decision_card_md: Pre-rendered markdown from render_decision_card()
        """
        body = f"{self.COMMENT_MARKER}\n\n{decision_card_md}"

        existing = self._find_existing_comment()
        if existing:
            existing.edit(body)
        else:
            self.pr.create_issue_comment(body)

    def post_approval_request(
        self,
        risk_tier: str,
        required_approvers: list[str] = None
    ) -> None:
        """
        Post a comment requesting approval from specific users.

        Args:
            risk_tier: Current risk tier
            required_approvers: List of GitHub usernames to request
        """
        lines = [
            self.COMMENT_MARKER + "-approval",
            "",
            f"## :rotating_light: Approval Required",
            "",
            f"This PR has been classified as **{risk_tier}** and requires human approval before merge.",
            "",
        ]

        if required_approvers:
            mentions = " ".join(f"@{u}" for u in required_approvers)
            lines.extend([
                f"**Requested reviewers:** {mentions}",
                "",
            ])

        lines.extend([
            "Please review the Diff Postcard above and:",
            "1. Verify the changes match the PR description",
            "2. Confirm risk assessment is appropriate",
            "3. Approve this PR to unblock merge",
            "",
        ])

        self.pr.create_issue_comment("\n".join(lines))
