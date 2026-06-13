# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 GuardSpine, Inc.
# Licensed under the Business Source License 1.1. See LICENSE for terms.
# Change License: Apache-2.0. Change Date: see LICENSE.
"""
SARIF Exporter - Exports findings in SARIF format for GitHub Security tab.

SARIF (Static Analysis Results Interchange Format) is the standard format
for static analysis tools. GitHub Code Scanning accepts SARIF uploads.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any


class SARIFExporter:
    """
    Exports GuardSpine findings in SARIF 2.1.0 format.

    This allows findings to appear in:
    - GitHub Security tab
    - Code scanning alerts
    - PR annotations
    """

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

    TOOL_NAME = "GuardSpine CodeGuard"
    TOOL_VERSION = "1.0.0"
    TOOL_URI = "https://github.com/marketplace/actions/guardspine-codeguard"

    # Map our severities to SARIF levels
    SEVERITY_TO_LEVEL = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    # Map our severities to SARIF security severity
    SEVERITY_TO_SECURITY = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "low",
    }

    def __init__(self):
        """Initialize SARIF exporter."""
        self.rules: dict[str, dict] = {}

    def export(
        self,
        findings: list[dict],
        repository: str,
        commit_sha: str,
        rubric: str = "default"
    ) -> dict[str, Any]:
        """
        Export findings to SARIF format.

        Args:
            findings: List of finding dicts from RiskClassifier
            repository: Repository name (owner/repo)
            commit_sha: Commit SHA being analyzed
            rubric: Rubric used for analysis

        Returns:
            Complete SARIF document as dict
        """
        self.rules = {}
        results = []

        for finding in findings:
            rule_id = finding.get("rule_id", finding.get("id", "unknown"))

            # Register rule if not seen
            if rule_id not in self.rules:
                self.rules[rule_id] = self._create_rule(finding)

            # Create result
            result = self._create_result(finding, rule_id)
            results.append(result)

        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "informationUri": self.TOOL_URI,
                            "rules": list(self.rules.values()),
                            "properties": {
                                "rubric": rubric,
                            }
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "versionControlProvenance": [
                        {
                            "repositoryUri": f"https://github.com/{repository}",
                            "revisionId": commit_sha,
                        }
                    ],
                }
            ],
        }

        return sarif

    def _create_rule(self, finding: dict) -> dict:
        """Create a SARIF rule definition from a finding."""
        rule_id = finding.get("rule_id", finding.get("id", "unknown"))
        severity = finding.get("severity", "medium")
        message = finding.get("message", "Policy violation detected")
        zone = finding.get("zone")

        # Determine rule category
        if zone:
            category = f"sensitive-{zone}"
            short_desc = f"Sensitive {zone} code modification"
        elif rule_id.startswith("RUBRIC-"):
            category = "compliance"
            short_desc = f"Compliance rule: {rule_id}"
        else:
            category = "security"
            short_desc = message[:60]

        rule = {
            "id": rule_id,
            "name": self._to_pascal_case(rule_id),
            "shortDescription": {
                "text": short_desc,
            },
            "fullDescription": {
                "text": message,
            },
            "defaultConfiguration": {
                "level": self.SEVERITY_TO_LEVEL.get(severity, "warning"),
            },
            "properties": {
                "category": category,
                "security-severity": self._security_score(severity),
                "tags": self._get_tags(finding),
            },
            "helpUri": f"{self.TOOL_URI}#rules",
        }

        return rule

    def _create_result(self, finding: dict, rule_id: str) -> dict:
        """Create a SARIF result from a finding."""
        severity = finding.get("severity", "medium")
        message = finding.get("message", "Policy violation detected")
        file_path = finding.get("file", "unknown")
        line = finding.get("line")

        result = {
            "ruleId": rule_id,
            "level": self.SEVERITY_TO_LEVEL.get(severity, "warning"),
            "message": {
                "text": message,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                    }
                }
            ],
            "fingerprints": {
                "guardspine/v1": self._compute_fingerprint(finding),
            },
        }

        # Add region if line number available
        if line:
            result["locations"][0]["physicalLocation"]["region"] = {
                "startLine": line,
            }

        # Add zone property if available
        zone = finding.get("zone")
        if zone:
            result["properties"] = {
                "sensitiveZone": zone,
            }

        return result

    def _security_score(self, severity: str) -> str:
        """
        Convert severity to CVSS-style score for GitHub security severity.

        GitHub uses these scores:
        - critical: 9.0-10.0
        - high: 7.0-8.9
        - medium: 4.0-6.9
        - low: 0.1-3.9
        """
        scores = {
            "critical": "9.5",
            "high": "7.5",
            "medium": "5.5",
            "low": "2.5",
            "info": "1.0",
        }
        return scores.get(severity, "5.5")

    def _get_tags(self, finding: dict) -> list[str]:
        """Get SARIF tags for a finding."""
        tags = ["guardspine"]

        zone = finding.get("zone")
        if zone:
            tags.append(f"sensitive-{zone}")

            # Add CWE mappings for common zones
            zone_cwes = {
                "auth": "CWE-287",      # Improper Authentication
                "payment": "CWE-311",   # Missing Encryption
                "crypto": "CWE-327",    # Broken Crypto
                "database": "CWE-89",   # SQL Injection potential
                "pii": "CWE-359",       # Privacy Violation
            }
            if zone in zone_cwes:
                tags.append(zone_cwes[zone])

        rule_id = finding.get("rule_id", "")
        if "CC" in rule_id:
            tags.append("soc2")
        elif "164" in rule_id:
            tags.append("hipaa")
        elif rule_id.replace(".", "").isdigit():
            tags.append("pci-dss")

        return tags

    def _compute_fingerprint(self, finding: dict) -> str:
        """Compute a stable fingerprint for deduplication."""
        content = "|".join([
            finding.get("rule_id", ""),
            finding.get("file", ""),
            str(finding.get("line", "")),
            finding.get("message", "")[:50],
        ])
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    def _to_pascal_case(self, text: str) -> str:
        """Convert rule ID to PascalCase name."""
        # Handle different formats
        text = text.replace("-", "_").replace(".", "_")
        parts = text.split("_")
        return "".join(p.capitalize() for p in parts if p)


def create_sarif_for_upload(
    findings: list[dict],
    repository: str,
    commit_sha: str,
    rubric: str = "default"
) -> str:
    """
    Convenience function to create SARIF JSON string ready for upload.

    Args:
        findings: List of findings
        repository: Repository name
        commit_sha: Commit SHA
        rubric: Rubric name

    Returns:
        SARIF document as JSON string
    """
    import json
    exporter = SARIFExporter()
    sarif = exporter.export(findings, repository, commit_sha, rubric)
    return json.dumps(sarif, indent=2)
