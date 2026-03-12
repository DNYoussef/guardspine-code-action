"""
Risk Classifier - Assigns risk tiers (L0-L4) based on analysis.
"""

from __future__ import annotations

import re
import copy
import fnmatch
from pathlib import Path
from typing import Any, TYPE_CHECKING
from dataclasses import dataclass

import yaml

if TYPE_CHECKING:
    from .analyzer import AnalysisResult

@dataclass
class Finding:
    """A policy finding."""
    id: str
    severity: str  # info, low, medium, high, critical
    message: str
    file: str
    line: int | None
    rule_id: str
    zone: str | None = None
    provable: bool = True


class RiskClassifier:
    """
    Classifies code changes into risk tiers.

    L0: Trivial - docs, comments, formatting
    L1: Low - minor changes, tests
    L2: Medium - feature code, non-sensitive
    L3: High - sensitive areas, needs review
    L4: Critical - security, payments, PII
    """

    # File patterns for risk assessment
    FILE_PATTERNS = {
        "L0": [
            r"\.md$", r"\.txt$", r"\.rst$",  # docs
            r"LICENSE", r"CHANGELOG", r"README",
            r"\.gitignore$", r"\.editorconfig$",
        ],
        "L1": [
            r"test[s]?/", r"spec[s]?/", r"__test__",
            r"\.test\.", r"\.spec\.", r"_test\.py$",
            r"mock", r"fixture",
        ],
        "L3": [
            r"auth", r"login", r"session",
            r"permission", r"role", r"access",
            r"middleware", r"interceptor",
            r"config", r"setting", r"\.env",
        ],
        "L4": [
            r"payment", r"billing", r"transaction",
            r"credit", r"stripe", r"paypal",
            r"encrypt", r"decrypt", r"secret",
            r"password", r"credential", r"token",
            r"ssn", r"social.security", r"pii",
            r"hipaa", r"gdpr", r"compliance",
        ],
    }

    # Legacy built-in rules used as fallback when rubric YAML files are unavailable.
    LEGACY_RUBRICS = {
        "default": {},
        "soc2": {
            "CC6.1": {"pattern": r"(auth|access|permission)", "severity": "high", "message": "Change management control affected"},
            "CC6.2": {"pattern": r"(user|account|provision)", "severity": "medium", "message": "Access provisioning affected"},
            "CC7.1": {"pattern": r"(CVE|vulnerab|patch|security)", "severity": "critical", "message": "Vulnerability management"},
            "CC8.1": {"pattern": r"(terraform|kubernetes|docker|infra)", "severity": "high", "message": "Infrastructure change"},
        },
        "hipaa": {
            "164.312.a": {"pattern": r"(phi|patient|medical|health)", "severity": "critical", "message": "PHI access control affected"},
            "164.312.b": {"pattern": r"(audit|log|trail)", "severity": "high", "message": "Audit control affected"},
            "164.312.e": {"pattern": r"(encrypt|tls|ssl|https)", "severity": "critical", "message": "Transmission security"},
        },
        "pci-dss": {
            "3.4": {"pattern": r"(pan|card.number|credit)", "severity": "critical", "message": "Cardholder data handling"},
            "6.5": {"pattern": r"(sql|inject|xss|csrf)", "severity": "critical", "message": "Secure coding requirement"},
            "8.3": {"pattern": r"(password|mfa|auth)", "severity": "high", "message": "Authentication control"},
        },
    }
    # Backward-compatible alias used by older tests/callers.
    RUBRICS = LEGACY_RUBRICS

    # Canonical aliases for shipped built-in rubric YAML files.
    BUILTIN_ALIASES = {
        "soc2": "soc2-controls",
        "hipaa": "hipaa-safeguards",
        "pci-dss": "pci-dss-requirements",
    }

    DEFAULT_ZONE_SEVERITY = {
        "payment": "critical",
        "crypto": "critical",
        "pii": "critical",
        "command_injection": "critical",
        "deserialization": "critical",
        "xss": "high",
        "auth": "high",
        "security": "high",
        "database": "high",
        "template_injection": "high",
        "path_traversal": "high",
        "weak_crypto": "high",
        "entropy_secret": "high",
        "config": "medium",
        "infra": "medium",
    }

    DEFAULT_SIZE_THRESHOLDS = {
        "large": 500,
        "medium": 100,
        "small": 20,
    }

    def __init__(
        self,
        rubric: str = "default",
        rubric_path: str | Path | None = None,
        policy_path: str | Path | None = None,
        repo_root: str | Path | None = None,
    ):
        """Initialize classifier with rubric and optional policy overrides."""
        self.rubric = rubric
        self.repo_root = Path(repo_root) if repo_root else None
        self.rubric_path = Path(rubric_path) if rubric_path else None
        self.builtin_rubrics = self.discover_builtin_rubrics(self.repo_root)

        if not self.rubric_path:
            self.rubric_path = self._resolve_rubric_path(rubric)

        # Mutable copies of defaults so policy overrides don't leak across runs
        self.file_patterns = copy.deepcopy(self.FILE_PATTERNS)
        self.zone_severity = dict(self.DEFAULT_ZONE_SEVERITY)
        self.size_thresholds = dict(self.DEFAULT_SIZE_THRESHOLDS)

        self.rubric_rules, self.rubric_errors = self._load_rubric_rules()

        if policy_path:
            self._load_policy(Path(policy_path))

    @classmethod
    def _builtin_dir_candidates(cls, repo_root: Path | None) -> list[Path]:
        """Return candidate directories for shipped built-in rubric YAML files."""
        candidates: list[Path] = []
        if repo_root:
            candidates.extend([
                repo_root / "rubrics" / "builtin",
                repo_root / ".guardspine" / "rubrics" / "builtin",
                repo_root / ".codeguard" / "rubrics" / "builtin",
            ])

        project_root = Path(__file__).resolve().parents[1]
        candidates.append(project_root / "rubrics" / "builtin")

        seen: set[Path] = set()
        unique: list[Path] = []
        for path in candidates:
            if path in seen:
                continue
            seen.add(path)
            unique.append(path)
        return unique

    @classmethod
    def discover_builtin_rubrics(cls, repo_root: str | Path | None = None) -> dict[str, Path]:
        """Discover built-in rubric YAML files and expose canonical aliases."""
        root = Path(repo_root) if repo_root else None
        discovered: dict[str, Path] = {}
        for directory in cls._builtin_dir_candidates(root):
            if not directory.exists():
                continue
            for ext in ("*.yaml", "*.yml"):
                for file_path in directory.glob(ext):
                    stem = file_path.stem
                    discovered.setdefault(stem, file_path)

        # Alias canonical short names to shipped filenames.
        for alias, stem in cls.BUILTIN_ALIASES.items():
            if stem in discovered:
                discovered.setdefault(alias, discovered[stem])
        return discovered

    @classmethod
    def builtin_names(cls, repo_root: str | Path | None = None) -> set[str]:
        """Return all known built-in rubric names (discovered + legacy)."""
        names = set(cls.LEGACY_RUBRICS.keys())
        names.update(cls.discover_builtin_rubrics(repo_root).keys())
        return names

    def _resolve_rubric_path(self, rubric: str) -> Path | None:
        """Resolve rubric name/path to a concrete YAML file path when available."""
        if rubric in self.builtin_rubrics:
            return self.builtin_rubrics[rubric]

        candidates: list[Path] = []
        raw = Path(rubric)
        if raw.is_absolute():
            candidates.append(raw)
        else:
            if self.repo_root:
                candidates.append(self.repo_root / raw)
            candidates.append(raw)

        repo_dirs: list[Path] = []
        if self.repo_root:
            repo_dirs.extend([
                self.repo_root / ".codeguard" / "rubrics",
                self.repo_root / ".github" / "codeguard" / "rubrics",
                self.repo_root / "rubrics",
                self.repo_root / ".guardspine" / "rubrics",
            ])

        for directory in repo_dirs:
            candidates.append(directory / rubric)

        expanded: list[Path] = []
        for candidate in candidates:
            expanded.append(candidate)
            if candidate.suffix.lower() not in (".yaml", ".yml"):
                expanded.append(candidate.with_suffix(".yaml"))
                expanded.append(candidate.with_suffix(".yml"))

        for candidate in expanded:
            if candidate.exists():
                return candidate
        return None

    def _load_rubric_rules(self) -> tuple[list[dict], list[str]]:
        """Load rubric rules from built-ins or a YAML file."""
        rules: list[dict] = []
        errors: list[str] = []

        if self.rubric_path:
            if not self.rubric_path.exists():
                raise FileNotFoundError(f"Rubric file not found: {self.rubric_path}")
            try:
                raw = yaml.safe_load(self.rubric_path.read_text()) or {}
            except Exception as exc:
                raise ValueError(f"Failed to parse rubric YAML {self.rubric_path}: {exc}") from exc

            raw_rules = raw.get("rules") if isinstance(raw, dict) else raw
            if isinstance(raw_rules, dict):
                iterable = []
                for rid, val in raw_rules.items():
                    if isinstance(val, dict):
                        iterable.append({"id": rid, **val})
                    else:
                        iterable.append({"id": rid, "pattern": str(val)})
            elif isinstance(raw_rules, list):
                iterable = raw_rules
            else:
                iterable = []

            for idx, rule in enumerate(iterable):
                if not isinstance(rule, dict):
                    errors.append(f"Rule {idx} skipped: invalid rule shape")
                    continue

                rid = str(rule.get("id") or f"rule_{idx}")
                raw_patterns: list[str] = []
                if isinstance(rule.get("pattern"), str):
                    raw_patterns.append(rule["pattern"])
                patterns = rule.get("patterns")
                if isinstance(patterns, list):
                    raw_patterns.extend([p for p in patterns if isinstance(p, str)])
                elif isinstance(patterns, str):
                    raw_patterns.append(patterns)

                compiled_patterns: list[re.Pattern] = []
                for raw_pattern in raw_patterns:
                    try:
                        compiled_patterns.append(re.compile(raw_pattern, re.IGNORECASE))
                    except Exception as exc:
                        errors.append(f"Rule {rid} skipped pattern {raw_pattern!r}: {exc}")

                if not compiled_patterns:
                    if not raw_patterns:
                        errors.append(f"Rule {rid} skipped: no valid pattern(s)")
                    continue

                exceptions = rule.get("exceptions", [])
                if isinstance(exceptions, str):
                    exceptions = [exceptions]
                elif not isinstance(exceptions, list):
                    exceptions = []

                rules.append({
                    "id": rid,
                    "severity": rule.get("severity", "medium"),
                    "message": (
                        rule.get("message")
                        or rule.get("description")
                        or "Policy rule triggered"
                    ),
                    "pattern": raw_patterns[0],
                    "patterns": raw_patterns,
                    "compiled": compiled_patterns[0],  # backwards compatibility
                    "compiled_patterns": compiled_patterns,
                    "exceptions": [str(e) for e in exceptions],
                })
        else:
            for rid, rule in self.LEGACY_RUBRICS.get(self.rubric, {}).items():
                try:
                    compiled = re.compile(rule["pattern"], re.IGNORECASE)
                except Exception as exc:
                    errors.append(f"Rule {rid} skipped: {exc}")
                    compiled = None
                rules.append({
                    "id": rid,
                    "severity": rule.get("severity", "medium"),
                    "message": rule.get("message", "Policy rule triggered"),
                    "pattern": rule.get("pattern", ""),
                    "compiled": compiled,
                })

        for err in errors:
            self._warn(err)
        return rules, errors

    def _validate_policy(self, policy: dict[str, Any], path: Path) -> None:
        """Validate policy schema strictly and reject unknown/pack-style keys."""
        if not isinstance(policy, dict):
            raise ValueError(f"Policy {path} must be a YAML object")

        allowed = {"file_patterns", "zone_severity", "size_thresholds"}
        unknown = sorted(set(policy.keys()) - allowed)
        if unknown:
            raise ValueError(
                f"Unsupported key(s) in risk policy {path}: {', '.join(unknown)}. "
                "Only file_patterns, zone_severity, size_thresholds are allowed."
            )

        patterns = policy.get("file_patterns", {})
        if patterns is not None:
            if not isinstance(patterns, dict):
                raise ValueError(f"file_patterns in {path} must be a map")
            valid_tiers = {"L0", "L1", "L3", "L4"}
            for tier, values in patterns.items():
                if tier not in valid_tiers:
                    raise ValueError(f"Invalid file_patterns tier {tier} in {path}")
                if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                    raise ValueError(f"file_patterns[{tier}] in {path} must be a list[str]")

        zone_severity = policy.get("zone_severity", {})
        if zone_severity is not None:
            if not isinstance(zone_severity, dict):
                raise ValueError(f"zone_severity in {path} must be a map")
            valid = {"critical", "high", "medium", "low", "info"}
            for zone, severity in zone_severity.items():
                if not isinstance(zone, str) or not isinstance(severity, str):
                    raise ValueError(f"zone_severity entries in {path} must be string pairs")
                if severity not in valid:
                    raise ValueError(f"zone_severity[{zone}] in {path} has invalid level {severity}")

        size_thresholds = policy.get("size_thresholds", {})
        if size_thresholds is not None:
            if not isinstance(size_thresholds, dict):
                raise ValueError(f"size_thresholds in {path} must be a map")
            required = {"large", "medium", "small"}
            missing = sorted(required - set(size_thresholds.keys()))
            if missing:
                raise ValueError(f"size_thresholds in {path} missing key(s): {', '.join(missing)}")
            try:
                large = int(size_thresholds["large"])
                medium = int(size_thresholds["medium"])
                small = int(size_thresholds["small"])
            except Exception as exc:
                raise ValueError(f"size_thresholds in {path} must be integers") from exc
            if not (large > medium > small >= 0):
                raise ValueError(
                    f"size_thresholds in {path} must satisfy large > medium > small >= 0"
                )

    def _load_policy(self, path: Path) -> None:
        """Load risk policy YAML to override patterns and thresholds."""
        if not path.exists():
            raise FileNotFoundError(f"Risk policy file not found: {path}")

        try:
            policy = yaml.safe_load(path.read_text()) or {}
        except Exception as exc:
            raise ValueError(f"Failed to parse risk policy {path}: {exc}") from exc

        self._validate_policy(policy, path)

        patterns = policy.get("file_patterns")
        if isinstance(patterns, dict):
            for tier, values in patterns.items():
                self.file_patterns[tier] = values

        zone_severity = policy.get("zone_severity")
        if isinstance(zone_severity, dict):
            for zone, sev in zone_severity.items():
                self.zone_severity[zone] = sev

        size_thresholds = policy.get("size_thresholds")
        if isinstance(size_thresholds, dict):
            self.size_thresholds["large"] = int(size_thresholds["large"])
            self.size_thresholds["medium"] = int(size_thresholds["medium"])
            self.size_thresholds["small"] = int(size_thresholds["small"])

    def _warn(self, message: str) -> None:
        """Emit a warning in GitHub Actions-friendly format."""
        print(f"::warning::{message}")

    @staticmethod
    def _downgrade_severity(severity: str) -> str:
        """Downgrade severity by one level."""
        return {"critical": "high", "high": "medium", "medium": "low", "low": "info"}.get(severity, severity)

    def classify(self, analysis: AnalysisResult | dict[str, Any]) -> dict[str, Any]:
        """
        Classify risk based on analysis results.

        Uses three signal sources:
          1. Zone-based keyword findings (deterministic)
          2. Rubric rule findings (deterministic)
          3. AI multi-model consensus (when available) to modulate severity

        Returns:
            Dict with: risk_tier, risk_drivers, findings, rationale
        """
        files = analysis.get("files", [])
        sensitive_zones = analysis.get("sensitive_zones", [])
        ai_summary = analysis.get("ai_summary", {})

        # Calculate scores
        file_score = self._score_files(files)
        zone_score = self._score_zones(sensitive_zones)
        size_score = self._score_size(analysis)

        # Collect findings
        findings = self._collect_findings(files, sensitive_zones)

        # Apply rubric rules
        rubric_findings = self._apply_rubric(files)
        findings.extend(rubric_findings)

        # --- AI Consensus Modulation ---
        # When AI models reviewed the diff, use their consensus to adjust
        # finding severity. This reduces FPs (AI approves benign keyword
        # matches) and catches FNs (AI flags issues rules missed).
        consensus_risk = analysis.get("consensus_risk", "")
        agreement_score = analysis.get("agreement_score", 0.0)

        if consensus_risk == "approve" and agreement_score >= 0.6:
            # AI majority approved: double-downgrade zone-only findings.
            # Threshold 0.6 = simple majority (2/3 at L3, unanimous at L1/L2).
            # Double downgrade (critical->medium, high->low) drops findings
            # below DecisionEngine condition_rules (high+provable), making
            # them advisory-only. Semantically correct: zone findings are
            # keyword matches, and the AI confirmed they're safe.
            # Rubric findings are NOT downgraded (they are organizational policy).
            for f in findings:
                if f.zone and not f.rule_id.startswith("RUBRIC"):
                    original = f.severity
                    f.severity = self._downgrade_severity(f.severity)
                    f.severity = self._downgrade_severity(f.severity)
                    # Never downgrade critical deterministic signals below "high".
                    if original == "critical" and f.severity in ("medium", "low", "info"):
                        f.severity = "high"

        elif consensus_risk == "request_changes" and agreement_score >= 0.6:
            # AI flagged issues: upgrade medium findings to high.
            # Gate: >= 0.6 agreement means majority of models flagged concerns.
            # With strictest-wins consensus (Patch 2), agreement_score now measures
            # fraction that said request_changes, so 0.6 = true majority.
            for f in findings:
                if f.severity == "medium":
                    f.severity = "high"
            # Inject AI concern findings (non-provable, so they can only
            # trigger MERGE-WITH-CONDITIONS via DecisionEngine, never BLOCK)
            mmr = analysis.get("multi_model_review", {})
            ai_concerns = []
            if mmr.get("consensus"):
                ai_concerns = mmr["consensus"].get("combined_concerns", [])
            elif ai_summary.get("concerns"):
                ai_concerns = ai_summary["concerns"]
            for idx, concern in enumerate(ai_concerns[:3]):
                findings.append(Finding(
                    id=f"AI-CONCERN-{idx}",
                    severity="high",
                    message=f"AI concern: {concern}",
                    file="",
                    line=None,
                    rule_id="ai-consensus",
                    zone=None,
                    provable=False,
                ))

        elif consensus_risk == "request_changes":
            # Single dissenter flagged but majority approved.
            # Don't escalate, but still inject AI concern findings as medium
            # (advisory only, won't trigger CONDITIONS).
            mmr = analysis.get("multi_model_review", {})
            ai_concerns = []
            if mmr.get("consensus"):
                ai_concerns = mmr["consensus"].get("combined_concerns", [])
            elif ai_summary.get("concerns"):
                ai_concerns = ai_summary["concerns"]
            for idx, concern in enumerate(ai_concerns[:3]):
                findings.append(Finding(
                    id=f"AI-MINORITY-{idx}",
                    severity="medium",
                    message=f"AI minority concern: {concern}",
                    file="",
                    line=None,
                    rule_id="ai-consensus",
                    zone=None,
                    provable=False,
                ))

        elif consensus_risk == "comment":
            # AI is uncertain: single-downgrade zone findings (soften keyword
            # matches the AI couldn't confirm) and inject medium-severity
            # findings from AI concerns for the evidence bundle.
            for f in findings:
                if f.zone and not f.rule_id.startswith("RUBRIC"):
                    f.severity = self._downgrade_severity(f.severity)
            mmr = analysis.get("multi_model_review", {})
            ai_concerns = []
            if mmr.get("consensus"):
                ai_concerns = mmr["consensus"].get("combined_concerns", [])
            elif ai_summary.get("concerns"):
                ai_concerns = ai_summary["concerns"]
            for idx, concern in enumerate(ai_concerns[:3]):
                findings.append(Finding(
                    id=f"AI-COMMENT-{idx}",
                    severity="medium",
                    message=f"AI concern: {concern}",
                    file="",
                    line=None,
                    rule_id="ai-consensus",
                    zone=None,
                    provable=False,
                ))

        # Calculate risk drivers
        risk_drivers = self._calculate_drivers(
            files, sensitive_zones, findings, ai_summary
        )

        # Determine final tier
        max_score = max(file_score, zone_score, size_score)

        # Boost for rubric findings
        if any(f.severity == "critical" for f in findings):
            max_score = max(max_score, 4)
        elif any(f.severity == "high" for f in findings):
            max_score = max(max_score, 3)

        risk_tier = f"L{min(max_score, 4)}"

        result = {
            "risk_tier": risk_tier,
            "risk_drivers": risk_drivers,
            "findings": [self._finding_to_dict(f) for f in findings],
            "scores": {
                "file_patterns": file_score,
                "sensitive_zones": zone_score,
                "change_size": size_score,
            },
            "rationale": self._generate_rationale(risk_tier, risk_drivers, findings),
        }

        # Pass through deliberation metadata for observability
        mmr = analysis.get("multi_model_review", {})
        if mmr.get("deliberation_rounds") is not None:
            result["deliberation_rounds"] = mmr["deliberation_rounds"]
            result["early_exit"] = mmr.get("early_exit", False)

        return result

    def _score_files(self, files: list) -> int:
        """Score based on file patterns."""
        max_score = 0

        for file in files:
            path = file.get("path", "")

            # Check L4 patterns first
            for pattern in self.file_patterns["L4"]:
                if re.search(pattern, path, re.IGNORECASE):
                    max_score = max(max_score, 4)

            for pattern in self.file_patterns["L3"]:
                if re.search(pattern, path, re.IGNORECASE):
                    max_score = max(max_score, 3)

            # L0 patterns reduce score (but don't override higher)
            is_trivial = any(
                re.search(p, path, re.IGNORECASE)
                for p in self.file_patterns["L0"]
            )
            is_test = any(
                re.search(p, path, re.IGNORECASE)
                for p in self.file_patterns["L1"]
            )

            if max_score == 0:
                if is_trivial:
                    max_score = 0
                elif is_test:
                    max_score = 1
                else:
                    max_score = 2

        return max_score

    def _score_zones(self, zones: list) -> int:
        """Score based on sensitive zones detected."""
        if not zones:
            return 0

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_score = 0

        for z in zones:
            sev = self.zone_severity.get(z.get("zone"), "medium")
            max_score = max(max_score, severity_rank.get(sev, 2))

        return max_score

    def _score_size(self, analysis: dict) -> int:
        """Score based on change size."""
        added = analysis.get("lines_added", 0)
        removed = analysis.get("lines_removed", 0)
        total = added + removed

        if total > self.size_thresholds["large"]:
            return 3  # Large changes need review
        elif total > self.size_thresholds["medium"]:
            return 2
        elif total > self.size_thresholds["small"]:
            return 1
        return 0

    def _collect_findings(self, files: list, zones: list) -> list[Finding]:
        """Collect findings from analysis."""
        findings = []
        seen: set[tuple[str, str, int | None]] = set()

        for zone in zones:
            key = (zone["zone"], zone.get("file", ""), zone.get("line"))
            if key in seen:
                continue
            seen.add(key)
            
            # Downgrade severity for test/fixture files
            file_path = zone.get("file", "")
            is_test = any(re.search(p, file_path, re.IGNORECASE) for p in self.file_patterns["L1"])
            
            base_severity = self.zone_severity.get(zone["zone"], "medium")
            severity = "info" if is_test else base_severity

            findings.append(Finding(
                id=f"ZONE-{zone['zone'].upper()}",
                severity=severity,
                message=f"Sensitive {zone['zone']} code modified",
                file=zone["file"],
                line=zone.get("line"),
                rule_id=f"sensitive-{zone['zone']}",
                zone=zone["zone"]
            ))

        return findings

    def _find_match_line(self, patterns: list[re.Pattern], file: dict) -> int | None:
        """Return first matching line number for a rule within a file change."""
        for hunk in file.get("hunks", []):
            for line in hunk.get("lines", []):
                if line.get("type") not in ("add", "remove"):
                    continue
                try:
                    content = line.get("content", "")
                    for pattern in patterns:
                        if pattern.search(content):
                            return line.get("line_number")
                except re.error as exc:
                    self._warn(f"Rubric regex error: {exc}")
                    return None
        return None

    def _apply_rubric(self, files: list) -> list[Finding]:
        """Apply rubric-specific rules."""
        findings = []

        for file in files:
            path = file.get("path", "")
            for rule in self.rubric_rules:
                compiled_patterns = rule.get("compiled_patterns") or []
                if not compiled_patterns:
                    continue

                exceptions = rule.get("exceptions", [])
                if any(fnmatch.fnmatch(path, ex) for ex in exceptions):
                    continue

                try:
                    matched_line = self._find_match_line(compiled_patterns, file)
                    path_match = any(p.search(path) for p in compiled_patterns)
                    if matched_line is None and not path_match:
                        continue
                except re.error as exc:
                    self._warn(f"Rubric rule {rule.get('id')} skipped: {exc}")
                    continue

                is_test = any(re.search(p, path, re.IGNORECASE) for p in self.file_patterns["L1"])
                base_severity = rule.get("severity", "medium")
                severity = "info" if is_test else base_severity

                findings.append(Finding(
                    id=f"RUBRIC-{rule.get('id')}",
                    severity=severity,
                    message=rule.get("message", "Policy rule triggered"),
                    file=path,
                    line=matched_line,
                    rule_id=rule.get("id", ""),
                ))

        return findings

    def _calculate_drivers(
        self, files: list, zones: list, findings: list, ai_summary: dict
    ) -> list[dict]:
        """Calculate top risk drivers."""
        drivers = []

        # Zone-based drivers - include affected files so reviewers know WHERE
        zone_info: dict[str, dict] = {}
        for z in zones:
            zn = z["zone"]
            if zn not in zone_info:
                zone_info[zn] = {"count": 0, "locations": []}
            zone_info[zn]["count"] += 1
            loc = z.get("file", "")
            line = z.get("line")
            ref = f"{loc}:{line}" if loc and line else loc
            if ref and ref not in zone_info[zn]["locations"]:
                zone_info[zn]["locations"].append(ref)

        for zone, info in sorted(zone_info.items(), key=lambda x: -x[1]["count"])[:3]:
            locs = info["locations"][:3]  # top 3 locations
            loc_str = ", ".join(f"`{l}`" for l in locs)
            if len(info["locations"]) > 3:
                loc_str += f" +{len(info['locations']) - 3} more"
            desc = f"{info['count']} changes in {zone} code"
            if loc_str:
                desc += f" ({loc_str})"
            drivers.append({
                "type": "sensitive_zone",
                "zone": zone,
                "count": info["count"],
                "locations": info["locations"],
                "description": desc,
            })

        # Finding-based drivers - include file/line
        for finding in sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2}.get(f.severity, 3))[:3]:
            desc = finding.message
            if finding.file:
                loc = finding.file
                if finding.line:
                    loc += f":{finding.line}"
                desc += f" (`{loc}`)"
            drivers.append({
                "type": "policy_finding",
                "rule": finding.rule_id,
                "severity": finding.severity,
                "file": finding.file,
                "line": finding.line,
                "description": desc,
            })

        # AI-based drivers
        if ai_summary.get("concerns"):
            for concern in ai_summary["concerns"][:2]:
                drivers.append({
                    "type": "ai_concern",
                    "description": concern
                })

        return drivers[:5]  # Top 5 drivers

    def _finding_to_dict(self, finding: Finding) -> dict:
        """Convert Finding to dict."""
        return {
            "id": finding.id,
            "severity": finding.severity,
            "message": finding.message,
            "file": finding.file,
            "line": finding.line,
            "rule_id": finding.rule_id,
            "zone": finding.zone,
            "provable": finding.provable,
        }

    def _generate_rationale(self, tier: str, drivers: list, findings: list) -> str:
        """Generate human-readable rationale."""
        if tier == "L0":
            return "Trivial change (documentation, formatting, or configuration only)"
        elif tier == "L1":
            return "Low-risk change (tests or non-critical code)"
        elif tier == "L2":
            return "Medium-risk change (feature code, review recommended)"
        elif tier == "L3":
            top_driver = drivers[0]["description"] if drivers else "sensitive code detected"
            return f"High-risk change: {top_driver}. Human approval required."
        else:  # L4
            critical_findings = [f for f in findings if f.severity == "critical"]
            if critical_findings:
                return f"Critical risk: {critical_findings[0].message}. Executive approval may be required."
            return "Critical risk: security, payment, or PII code affected. Executive approval required."
