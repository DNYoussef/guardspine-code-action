# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 GuardSpine, Inc.
# Licensed under the Business Source License 1.1. See LICENSE for terms.
# Change License: Apache-2.0. Change Date: see LICENSE.
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

try:  # mirrors analyzer's own package/top-level import shim
    from .analyzer import AI_UNAVAILABLE_PREFIX
except ImportError:  # pragma: no cover - import-path shim for test layout
    from analyzer import AI_UNAVAILABLE_PREFIX

try:
    from .severity import normalize_severity, severity_rank, validate_severity
except ImportError:  # pragma: no cover - supports direct src/ path imports
    from severity import normalize_severity, severity_rank, validate_severity

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
    control_category: str | None = None  # compliance control family, e.g. "CC-AccessControl"
    control_name: str | None = None      # human control name, e.g. "Change Management"
    # Which rubric pack produced this finding. Load-bearing once a repo selects
    # several packs at once: without it "which pack flagged this?" is
    # unanswerable, and a merged rule set is an opaque blob to the reviewer.
    source_pack: str | None = None
    # `provable` defaults to FALSE: a finding earns hard-block authority only
    # by being a deterministic detection (AST/dataflow/entropy). Everything
    # produced here -- sensitive-zone keyword matches and rubric regex rules --
    # is a heuristic and must NOT be provable, no matter its rule_id or
    # severity. A genuine deterministic detector opts in with provable=True
    # explicitly. This is the single invariant that makes decision==block mean
    # "provable danger" rather than "a keyword appeared."
    provable: bool = False

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)


def _ai_consensus_finding(idx: int, concern: str, *, severity: str, label: str) -> "Finding":
    """Turn one aggregated model concern into a finding.

    Two kinds arrive on the same list of strings. A concern is normally
    something a reviewer model noticed about the diff. But a review that never
    ran also lands here, and labelling an unreachable provider "AI concern"
    tells the reviewer their code has a problem it does not have -- and teaches
    them these findings are noise, which is the one thing a governance product
    cannot afford.

    The unavailability text is emitted by analyzer._fail_closed_review and is
    already safe to publish: the provider's raw exception carries our user id,
    routing and billing state, and is kept out of the concern deliberately.
    """
    if concern.startswith(AI_UNAVAILABLE_PREFIX):
        return Finding(
            id=f"AI-UNAVAILABLE-{idx}",
            severity=severity,
            message=concern,
            file="",
            line=None,
            # Its own rule id: this is a statement about coverage, and a
            # reviewer filtering ai-consensus findings should still see it.
            rule_id="ai-availability",
            zone=None,
            provable=False,
        )
    return Finding(
        id=f"{label}-{idx}",
        severity=severity,
        message=f"{'AI concern' if label == 'AI-CONCERN' else 'AI minority concern'}: {concern}",
        file="",
        line=None,
        rule_id="ai-consensus",
        zone=None,
        provable=False,
    )


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
        rubric_explicit: bool | None = None,
        config_packs: list[str] | None = None,
    ):
        """Initialize classifier with rubric and optional policy overrides."""
        self.rubric = rubric
        self.repo_root = Path(repo_root) if repo_root else None
        self.rubric_path = Path(rubric_path) if rubric_path else None
        self.builtin_rubrics = self.discover_builtin_rubrics(self.repo_root)

        # An explicit rubric choice always wins, so upgrading the Action never
        # changes an existing workflow's behavior. The caller states whether the
        # choice was explicit, because it is the only layer that can tell: by the
        # time a name reaches here, an omitted input and `rubric: default` look
        # identical, and entrypoint eagerly resolves "default" to the shipped
        # default.yaml so "was a path supplied?" cannot answer it either.
        if rubric_explicit is None:
            rubric_explicit = bool(rubric_path) or rubric != "default"
        # config_packs is supplied BY THE CALLER and must come from a source the
        # PR author cannot edit (see entrypoint: it is read from the base ref).
        # The classifier deliberately does not read .guardspine/config.yml from
        # the workspace: actions/checkout gives us the PR head, so a PR could
        # otherwise ship a one-rule pack that matches nothing, point the config
        # at it, and be judged by a policy it wrote for itself.
        self.config_packs: list[str] = [] if rubric_explicit else list(config_packs or [])

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
        """Return candidate directories for built-in rubric YAML files.

        SHIPPED FIRST, deliberately. discover_builtin_rubrics() keeps the first
        match for a given stem, so whichever directory comes first wins. With
        repo paths first, a PR could commit rubrics/builtin/hipaa-safeguards.yaml
        containing one rule that matches nothing and an explicit `rubric: hipaa`
        would load THAT instead of the real pack -- a PR neutering the control
        that judges it (reproduced: only the PR's NOOP rule loaded).

        Repo directories are still searched, so a repo can add rubrics of its
        own; it simply cannot take over a name the Action ships.
        """
        candidates: list[Path] = []

        project_root = Path(__file__).resolve().parents[1]
        candidates.append(project_root / "rubrics" / "builtin")

        if repo_root:
            candidates.extend([
                repo_root / "rubrics" / "builtin",
                repo_root / ".guardspine" / "rubrics" / "builtin",
                repo_root / ".codeguard" / "rubrics" / "builtin",
            ])

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
    def parse_config_packs(cls, config_text: str) -> list[str]:
        """Extract a normalized `rubric_packs` list from config.yml TEXT.

        Takes TEXT, not a path, so the caller decides where the config came
        from. That is the entire trust boundary: config read from the PR
        checkout would let a PR choose the policy that judges it (ship a
        one-rule pack matching nothing, point rubric_packs at it, get a clean
        scan). entrypoint reads it from the base ref.

        Returns [] for anything unusable -- this must never break a scan for a
        repo that does not use the feature.
        """
        try:
            raw = yaml.safe_load(config_text) or {}
        except Exception:
            return []
        if not isinstance(raw, dict):
            return []
        packs = raw.get("rubric_packs")
        if isinstance(packs, str):
            packs = [packs]
        if not isinstance(packs, list):
            return []

        # Aliases and their target stems are the same pack; collapse them so
        # ["hipaa", "hipaa-safeguards"] cannot load one pack's rules twice.
        seen: set[str] = set()
        names: list[str] = []
        for entry in packs:
            if not isinstance(entry, (str, int)):
                continue
            name = str(entry).strip()
            canonical = cls.BUILTIN_ALIASES.get(name, name)
            if not name or canonical in seen:
                continue
            seen.add(canonical)
            names.append(canonical)
            if len(names) >= cls.MAX_CONFIG_PACKS:
                break
        return names

    @classmethod
    def operational_rubric_packs(cls) -> dict[str, dict[str, int]]:
        """Report what each SHIPPED pack actually enforces.

        Returns {stem: {"declared": n, "compiled": m}}. A pack is only worth
        offering when compiled > 0: resolving a filename is not the same as
        working -- six-sigma.yaml ships 15 rules and zero patterns, so it loads
        cleanly and enforces nothing. Callers that build a picker must consult
        this rather than a directory listing.

        Deliberately takes no repo_root and builds no classifier: this describes
        the SHIPPED packs, and constructing a classifier per pack both costs
        ~165ms with 30+ spurious warnings and, for "default", recursively reads
        the repo's own config so the count came back wrong.
        """
        catalog: dict[str, dict[str, int]] = {}
        for stem, path in sorted(cls.discover_builtin_rubrics().items()):
            if stem in cls.BUILTIN_ALIASES:
                continue  # alias of a stem already listed; not a distinct pack
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                declared = raw.get("rules") if isinstance(raw, dict) else raw
                declared_n = len(declared) if isinstance(declared, (list, dict)) else 0
                compiled, _ = cls._parse_rubric_file(path, source_pack=stem)
            except Exception:
                continue
            catalog[stem] = {"declared": declared_n, "compiled": len(compiled)}
        return catalog

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

    @staticmethod
    def _parse_rubric_file(
        path: Path, source_pack: str | None = None
    ) -> tuple[list[dict], list[str]]:
        """Parse ONE rubric YAML into compiled rule dicts + errors.

        Split out of _load_rubric_rules so the same parsing/compiling path is
        reused for every pack in a multi-pack load -- a second parser would
        drift from this one (the repo already carries two rubric loaders that
        disagree about duplicate ids).

        source_pack is stamped on every rule so a finding can name the pack it
        came from; merging without it makes "which pack flagged this?"
        unanswerable.
        """
        rules: list[dict] = []
        errors: list[str] = []

        if not path.exists():
            raise FileNotFoundError(f"Rubric file not found: {path}")
        try:
            raw = yaml.safe_load(path.read_text()) or {}
        except Exception as exc:
            raise ValueError(f"Failed to parse rubric YAML {path}: {exc}") from exc

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

        prefix = f"[{source_pack}] " if source_pack else ""

        # The pack's display identity, stamped onto every rule. The reviewer
        # models are shown these rules grouped by pack (see
        # rubric_prompt_packs), and a finding that cites "SOX-302" is only
        # useful if the block above it names SOX ITGC. Carried on the rule
        # rather than in a side table so there is one place a rule's origin
        # lives, and no second read of the YAML -- this file already warns
        # that a second parser drifts from this one.
        pack_name = raw.get("name") if isinstance(raw, dict) else None
        pack_version = raw.get("version") if isinstance(raw, dict) else None

        for idx, rule in enumerate(iterable):
            if not isinstance(rule, dict):
                errors.append(f"{prefix}Rule {idx} skipped: invalid rule shape")
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
                    errors.append(f"{prefix}Rule {rid} skipped pattern {raw_pattern!r}: {exc}")

            if not compiled_patterns:
                if not raw_patterns:
                    errors.append(f"{prefix}Rule {rid} skipped: no valid pattern(s)")
                continue

            exceptions = rule.get("exceptions", [])
            if isinstance(exceptions, str):
                exceptions = [exceptions]
            elif not isinstance(exceptions, list):
                exceptions = []

            rules.append({
                "id": rid,
                "severity": normalize_severity(rule.get("severity", "medium")),
                "message": (
                    rule.get("message")
                    or rule.get("description")
                    or "Policy rule triggered"
                ),
                "control_category": rule.get("category"),
                "control_name": rule.get("name"),
                "pattern": raw_patterns[0],
                "patterns": raw_patterns,
                "compiled": compiled_patterns[0],  # backwards compatibility
                "compiled_patterns": compiled_patterns,
                "exceptions": [str(e) for e in exceptions],
                "source_pack": source_pack,
                "pack_name": pack_name or source_pack,
                "pack_version": pack_version,
            })

        return rules, errors

    def rubric_prompt_packs(self) -> list[dict]:
        """The loaded rules, shaped for the reviewer models' prompt.

        A rubric is not only a regex list -- it is what the models are told to
        look for once the risk tier decides they should look. Built from
        self.rubric_rules so the models and the regex evaluator see the SAME
        rules: anything the evaluator could not load is not claimed to the
        model either, and anything the evaluator enforces is stated.

        Grouped by pack and in load order, because a finding citing SOX-302
        means nothing unless the block naming SOX ITGC sits above it.
        """
        packs: dict[str, dict] = {}
        for rule in self.rubric_rules:
            key = rule.get("source_pack") or self.rubric
            pack = packs.setdefault(key, {
                "name": rule.get("pack_name") or key,
                "version": rule.get("pack_version") or "?",
                "rules": [],
            })
            pack["rules"].append({
                "id": rule.get("id"),
                "severity": rule.get("severity"),
                # The loaded rule stores these under the names the evaluator
                # uses; the prompt renderer is shared with the spreadsheet lane
                # and expects a rubric's own vocabulary.
                "name": rule.get("control_name") or rule.get("id"),
                "description": rule.get("message") or "",
            })
        return list(packs.values())

    def _load_legacy_rubric_rules(self) -> tuple[list[dict], list[str]]:
        """Fallback rules for a builtin name with no shipped YAML."""
        rules: list[dict] = []
        errors: list[str] = []
        for rid, rule in self.LEGACY_RUBRICS.get(self.rubric, {}).items():
            try:
                compiled = re.compile(rule["pattern"], re.IGNORECASE)
            except Exception as exc:
                errors.append(f"Rule {rid} skipped: {exc}")
                compiled = None
            rules.append({
                "id": rid,
                "severity": normalize_severity(rule.get("severity", "medium")),
                "message": rule.get("message", "Policy rule triggered"),
                "pattern": rule.get("pattern", ""),
                "compiled": compiled,
                "source_pack": self.rubric,
            })
        return rules, errors

    def _load_rubric_rules(self) -> tuple[list[dict], list[str]]:
        """Load rubric rules from a config.yml pack list, a file, or built-ins.

        Precedence (highest first):
          1. an explicit rubric file/name on the workflow's `rubric:` input
          2. `rubric_packs:` in the repo's .guardspine/config.yml
          3. the legacy built-in table

        (2) exists because onboarding has always WRITTEN that list and the
        Action never read it, so every onboarded repo silently ran whatever
        single rubric its workflow hardcoded, ignoring its own config.
        """
        errors: list[str] = []

        if self.config_packs:
            rules, errors = self._load_pack_rules(self.config_packs)
            if not rules:
                # NEVER enforce less after an upgrade than before it. Every repo
                # onboarded to date carries a config listing "security-baseline"
                # and "pii-shield", neither of which is a real pack -- honoring
                # that list literally would take those repos from the default
                # rules to ZERO rules, silently disabling rubric enforcement
                # fleet-wide. An unusable pack list falls back to the previous
                # behavior, loudly.
                errors.append(
                    "No rubric_packs from .guardspine/config.yml could be loaded; "
                    f"falling back to rubric {self.rubric!r}"
                )
                self.config_packs = []
                fallback, fallback_errors = self._load_configured_rubric()
                rules, errors = fallback, errors + fallback_errors
        else:
            rules, errors = self._load_configured_rubric()

        for err in errors:
            self._warn(err)
        return rules, errors

    def _load_configured_rubric(self) -> tuple[list[dict], list[str]]:
        """Load the single rubric named by the `rubric:` input (pre-pack path)."""
        if self.rubric_path:
            return self._parse_rubric_file(self.rubric_path, source_pack=self.rubric)
        return self._load_legacy_rubric_rules()

    # A committed config is attacker-controlled (anyone who can open a PR can
    # edit it), so a pack name must never become an arbitrary filesystem read.
    MAX_CONFIG_PACKS = 32

    @classmethod
    def shipped_rubrics(cls) -> dict[str, Path]:
        """Rubric YAMLs packaged INSIDE the Action image.

        Deliberately excludes discover_builtin_rubrics()'s repo-root candidates:
        those scan directories the PR controls, and first-match-wins means a PR
        that drops its own rubrics/builtin/hipaa-safeguards.yaml would shadow the
        real pack. Only these paths are safe to resolve a config pack against.
        """
        shipped: dict[str, Path] = {}
        directory = Path(__file__).resolve().parents[1] / "rubrics" / "builtin"
        if directory.exists():
            for ext in ("*.yaml", "*.yml"):
                for file_path in directory.glob(ext):
                    shipped.setdefault(file_path.stem, file_path)
        for alias, stem in cls.BUILTIN_ALIASES.items():
            if stem in shipped:
                shipped.setdefault(alias, shipped[stem])
        return shipped

    def _resolve_pack_path(self, pack: str) -> Path | None:
        """Resolve a config pack name against SHIPPED packs only.

        Repo-local rubric files are intentionally NOT reachable from config:
        they live in the PR checkout, so honoring them would reintroduce the
        "a PR picks its own policy" hole from the other direction.

        NOTE, and it is important: the `rubric:` input is NOT a trusted
        alternative. On `pull_request` events GitHub runs the workflow file from
        the PR's merge commit, so a PR can edit `rubric:` -- or the whole
        workflow -- just as easily. An earlier version of this comment claimed
        the workflow came from the base branch; that is false and was the wrong
        basis for a security decision. The Action cannot defend its own
        invocation; that requires branch protection plus backend-side checking
        that the packs an org expects are the packs a scan actually reported.
        """
        return self.shipped_rubrics().get(pack)

    def _load_pack_rules(self, packs: list[str]) -> tuple[list[dict], list[str]]:
        """Load and concatenate several packs.

        Rules are kept per (pack, rule_id), NOT deduplicated by bare rule id.
        Two packs legitimately declaring the same id is not ambiguous once every
        finding carries its source_pack, and dropping a colliding rule would let
        one pack silently disable another pack's control -- weaker enforcement
        from a naming coincidence. The pack LIST is deduplicated instead, so a
        repeated name cannot double-report.
        """
        rules: list[dict] = []
        errors: list[str] = []

        for pack in packs:
            path = self._resolve_pack_path(pack)
            if path is None:
                errors.append(
                    f"Rubric pack {pack!r} from .guardspine/config.yml is not a "
                    "pack shipped with this Action; skipped. (Repo-local rubric "
                    "files are not selectable here -- point the workflow's "
                    "`rubric:` input at one instead.)"
                )
                continue
            try:
                pack_rules, pack_errors = self._parse_rubric_file(path, source_pack=pack)
            except (OSError, ValueError) as exc:
                errors.append(f"Rubric pack {pack!r} failed to load: {exc}")
                continue
            errors.extend(pack_errors)
            rules.extend(pack_rules)

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
                if severity.strip().lower() not in valid:
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
                self.zone_severity[zone] = validate_severity(
                    sev,
                    context=f"zone_severity[{zone}] in {path}",
                )

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

        # Calculate deterministic scores. AI review can add evidence, but it
        # must not lower the tier floor set by local checks.
        file_score = self._score_files(files)
        zone_score = self._score_zones(sensitive_zones)
        size_score = self._score_size(analysis)
        deterministic_score = max(file_score, zone_score, size_score)
        protect_deterministic_escalation = deterministic_score >= 3

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
            # AI majority approved: double-downgrade lower-tier zone findings.
            # Threshold 0.6 = simple majority (2/3 at L3, unanimous at L1/L2).
            # Double downgrade (critical->medium, high->low) drops findings
            # below DecisionEngine condition_rules (high+provable), making
            # them advisory-only. Semantically correct: zone findings are
            # keyword matches, and the AI confirmed they're safe.
            # Rubric findings are NOT downgraded (they are organizational policy).
            # Deterministic L3/L4 escalations are also not downgraded: model
            # approval is untrusted evidence and cannot bypass human review.
            for f in findings:
                if f.zone and not f.rule_id.startswith("RUBRIC"):
                    if protect_deterministic_escalation:
                        continue
                    original = f.severity
                    f.severity = self._downgrade_severity(f.severity)
                    f.severity = self._downgrade_severity(f.severity)
                    # Never downgrade critical deterministic checks below "high".
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
                findings.append(_ai_consensus_finding(
                    idx, concern, severity="high", label="AI-CONCERN"))

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
                findings.append(_ai_consensus_finding(
                    idx, concern, severity="medium", label="AI-MINORITY"))

        elif consensus_risk == "comment":
            # AI is uncertain: single-downgrade lower-tier zone findings (soften keyword
            # matches the AI couldn't confirm) and inject medium-severity
            # findings from AI concerns for the evidence bundle. Deterministic
            # L3/L4 escalations remain enforced.
            for f in findings:
                if f.zone and not f.rule_id.startswith("RUBRIC"):
                    if protect_deterministic_escalation:
                        continue
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
            files, sensitive_zones, findings, ai_summary, file_score
        )

        # Determine final tier. Start from the deterministic floor so model
        # output can never reduce L3/L4 escalation.
        max_score = deterministic_score

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
                "deterministic_floor": deterministic_score,
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
            max_score = max(max_score, self._classify_file_path(file.get("path", ""))["score"])

        return max_score

    def _classify_file_path(self, path: str) -> dict[str, Any]:
        """Return the highest-priority file-pattern classification for one path."""
        for tier, score in (("L4", 4), ("L3", 3), ("L1", 1), ("L0", 0)):
            matches = [
                pattern
                for pattern in self.file_patterns[tier]
                if re.search(pattern, path, re.IGNORECASE)
            ]
            if matches:
                return {"tier": tier, "score": score, "patterns": matches}

        return {"tier": "L2", "score": 2, "patterns": []}

    def _score_zones(self, zones: list) -> int:
        """Score based on sensitive zones detected."""
        if not zones:
            return 0

        max_score = 0

        for z in zones:
            sev = self.zone_severity.get(z.get("zone"), "medium")
            max_score = max(max_score, severity_rank(sev))

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

            # Deterministic secret_detector findings carry their OWN severity
            # and provable flag (keyed on detector=="secret", NOT the zone
            # name -- PII-Shield's entropy_secret label has no such flag and
            # stays non-provable). This is the ONLY finding source that may be
            # provable=True. Amendment 3: in a test/fixture file, force a
            # non-blocking condition (high, provable=False) -- a fake secret in
            # a fixture must never block, but stays visible.
            if zone.get("detector") == "secret":
                if is_test:
                    severity, provable = "high", False
                else:
                    severity = normalize_severity(zone.get("severity", "critical"))
                    provable = bool(zone.get("provable", False))
                kind = zone.get("secret_kind", "secret")
                findings.append(Finding(
                    id=f"SECRET-{kind.upper()}",
                    severity=severity,
                    message=f"Hardcoded secret detected ({kind})",
                    file=zone["file"],
                    line=zone.get("line"),
                    rule_id=f"secret-{kind}",
                    zone=zone["zone"],
                    provable=provable,
                ))
                continue

            base_severity = self.zone_severity.get(zone["zone"], "medium")
            severity = "info" if is_test else normalize_severity(base_severity)

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
                severity = "info" if is_test else normalize_severity(base_severity)

                findings.append(Finding(
                    id=f"RUBRIC-{rule.get('id')}",
                    severity=severity,
                    message=rule.get("message", "Policy rule triggered"),
                    file=path,
                    line=matched_line,
                    rule_id=rule.get("id", ""),
                    control_category=rule.get("control_category"),
                    control_name=rule.get("control_name"),
                    source_pack=rule.get("source_pack"),
                ))

        return findings

    def _calculate_drivers(
        self,
        files: list,
        zones: list,
        findings: list,
        ai_summary: dict,
        file_score: int,
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
        for finding in sorted(findings, key=lambda f: -severity_rank(f.severity))[:3]:
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

        if not drivers and file_score > 0:
            ranked_files = []
            for file in files:
                path = file.get("path", "")
                if not path:
                    continue
                classification = self._classify_file_path(path)
                ranked_files.append((classification["score"], path, classification))

            ranked_files.sort(key=lambda item: item[0], reverse=True)
            for score, path, classification in ranked_files[:3]:
                drivers.append({
                    "type": "file_pattern",
                    "tier": classification["tier"],
                    "score": score,
                    "file": path,
                    "matched_patterns": classification["patterns"][:3],
                    "description": (
                        f"File path `{path}` contributed {classification['tier']} risk scoring"
                    ),
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
            "control_category": finding.control_category,
            "control_name": finding.control_name,
            "provable": finding.provable,
            # Reaches the evidence bundle. NOT yet rendered in the PR decision
            # card or SARIF: entrypoint remaps these into decision_engine.Finding,
            # which has no pack field, and sarif_exporter ignores it. Surfacing
            # it there is separate work -- do not claim it here.
            "source_pack": finding.source_pack,
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
