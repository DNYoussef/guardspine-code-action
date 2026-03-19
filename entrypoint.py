#!/usr/bin/env python3
"""
GuardSpine CodeGuard GitHub Action Entrypoint

Analyzes PR diffs, evaluates risk, and generates evidence bundles.
"""

import json
import os
import sys
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from github import Auth, Github
from github.PullRequest import PullRequest

from src.analyzer import DiffAnalyzer
from src.risk_classifier import RiskClassifier
from src.bundle_generator import BundleGenerator
from src.confidence_calibrator import annotate_analysis_with_calibration, load_artifact
from src.pr_commenter import PRCommenter
from src.sarif_exporter import SARIFExporter
from src.pii_shield import PIIShieldClient, PIIShieldError

from src.decision_engine import Finding as AuditFinding, DecisionEngine, render_decision_card


def get_env(name: str, default: str = "") -> str:
    """Get environment variable with default."""
    return os.environ.get(name, default)


def parse_bool(value: str) -> bool:
    """Parse boolean from string."""
    return value.lower() in ("true", "1", "yes")


def parse_float(value: str, default: float) -> float:
    """Parse a float from string with fallback."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def resolve_path(raw: Optional[str], workspace: Path) -> Optional[Path]:
    """Resolve a possibly-relative path against the GitHub workspace."""
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate


def resolve_existing_file(
    raw: Optional[str],
    bases: list[Path],
    extensions: tuple[str, ...] = ("", ".yaml", ".yml"),
) -> Optional[Path]:
    """Resolve an input path/name to an existing file across base directories."""
    if not raw:
        return None

    candidate = Path(raw)
    roots = [Path(p) for p in bases]
    if candidate.is_absolute():
        roots = [Path(".")]
    elif Path(".") not in roots:
        roots.append(Path("."))

    seen: set[Path] = set()
    for root in roots:
        base = candidate if candidate.is_absolute() else (root / candidate)
        for ext in extensions:
            test = base if (ext == "" or base.suffix) else base.with_suffix(ext)
            resolved = test.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            if resolved.exists():
                return resolved
    return None


def _merge_sensitive_zones(
    base_zones: list[dict[str, Any]],
    extra_zones: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge sensitive zones without duplicate zone/file/line entries."""
    merged = list(base_zones or [])
    seen = {
        (
            z.get("zone"),
            z.get("file"),
            z.get("line"),
            z.get("content_preview"),
        )
        for z in merged
    }
    for zone in extra_zones or []:
        key = (
            zone.get("zone"),
            zone.get("file"),
            zone.get("line"),
            zone.get("content_preview"),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(zone)
    return merged


def _merge_redaction_counts(
    base: dict[str, int],
    extra: dict[str, int],
) -> dict[str, int]:
    merged = {str(k): int(v) for k, v in (base or {}).items()}
    for key, value in (extra or {}).items():
        merged[str(key)] = merged.get(str(key), 0) + int(value)
    return merged


def _init_sanitization_summary(
    pii_result: Any,
    salt_fingerprint: str,
) -> dict[str, Any]:
    details = pii_result.to_metadata().get("details", {})
    return {
        "engine_name": "pii-shield",
        "engine_version": str(details.get("engine_version") or details.get("schema_version") or "unknown"),
        "method": "provider_native" if pii_result.mode == "remote" else "deterministic_hmac",
        "token_format": "[HIDDEN:<id>]",
        "salt_fingerprint": salt_fingerprint,
        "redaction_count": 0,
        "redactions_by_type": {},
        "input_hash": pii_result.input_hash,
        "output_hash": pii_result.output_hash,
        "applied_to": [],
        "status": "none",
    }


def _record_sanitization_stage(
    summary: dict[str, Any] | None,
    stage: str,
    result: Any,
) -> dict[str, Any] | None:
    if summary is None:
        return None

    if stage not in summary["applied_to"]:
        summary["applied_to"].append(stage)

    summary["redaction_count"] += int(max(result.redaction_count, 0))
    summary["redactions_by_type"] = _merge_redaction_counts(
        summary.get("redactions_by_type", {}),
        result.redactions_by_type,
    )
    if result.changed:
        summary["status"] = "sanitized"
    elif summary["status"] == "none" and result.redaction_count > 0:
        summary["status"] = "partial"
    return summary


def main():
    """Main entrypoint for the action."""
    # Parse inputs from environment (set by GitHub Actions)
    risk_threshold = get_env("INPUT_RISK_THRESHOLD", "L3")
    rubric = get_env("INPUT_RUBRIC", "default")
    github_token = get_env("INPUT_GITHUB_TOKEN")
    post_comment = parse_bool(get_env("INPUT_POST_COMMENT", "true"))
    generate_bundle = parse_bool(get_env("INPUT_GENERATE_BUNDLE", "true"))
    upload_sarif = parse_bool(get_env("INPUT_UPLOAD_SARIF", "false"))
    fail_on_high_risk = parse_bool(get_env("INPUT_FAIL_ON_HIGH_RISK", "false"))

    # Optional AI API keys
    openai_key = get_env("INPUT_OPENAI_API_KEY") or get_env("OPENAI_API_KEY")
    anthropic_key = get_env("INPUT_ANTHROPIC_API_KEY") or get_env("ANTHROPIC_API_KEY")
    openrouter_key = get_env("INPUT_OPENROUTER_API_KEY") or get_env("OPENROUTER_API_KEY")
    openrouter_model = get_env("INPUT_OPENROUTER_MODEL", "anthropic/claude-sonnet-4.5")

    # Ollama for local/on-prem AI (no API key needed)
    ollama_host = get_env("INPUT_OLLAMA_HOST") or get_env("OLLAMA_HOST")
    ollama_model = get_env("INPUT_OLLAMA_MODEL", "llama3.3")

    # Multi-model configuration for tier-based review
    model_1 = get_env("INPUT_MODEL_1")  # Used for L1+
    model_2 = get_env("INPUT_MODEL_2")  # Used for L2+
    model_3 = get_env("INPUT_MODEL_3")  # Used for L3+
    ai_review = parse_bool(get_env("INPUT_AI_REVIEW", "true"))

    # Deliberation (multi-round cross-checking)
    deliberate = parse_bool(get_env("INPUT_DELIBERATE", "false"))

    # PII-Shield integration (privacy-preserving AI review input)
    pii_shield_enabled = parse_bool(get_env("INPUT_PII_SHIELD_ENABLED", "false"))
    pii_shield_mode = get_env("INPUT_PII_SHIELD_MODE", "auto")
    pii_shield_endpoint = get_env("INPUT_PII_SHIELD_ENDPOINT")
    pii_shield_api_key = get_env("INPUT_PII_SHIELD_API_KEY") or get_env("PII_SHIELD_API_KEY")
    pii_shield_timeout = parse_float(get_env("INPUT_PII_SHIELD_TIMEOUT", "5"), 5.0)
    pii_shield_fail_closed = parse_bool(get_env("INPUT_PII_SHIELD_FAIL_CLOSED", "true"))
    pii_shield_salt_fingerprint = get_env("INPUT_PII_SHIELD_SALT_FINGERPRINT", "sha256:00000000")
    pii_shield_sanitize_comments = parse_bool(get_env("INPUT_PII_SHIELD_SANITIZE_COMMENTS", "true"))
    pii_shield_sanitize_bundle = parse_bool(get_env("INPUT_PII_SHIELD_SANITIZE_BUNDLE", "true"))
    pii_shield_sanitize_sarif = parse_bool(get_env("INPUT_PII_SHIELD_SANITIZE_SARIF", "true"))
    pii_safe_regex_list = get_env(
        "INPUT_PII_SAFE_REGEX_LIST",
        '[{"pattern": "^[a-f0-9]{40,64}$", "name": "SafeGitSHA"}, {"pattern": "_hash$", "name": "HashFieldSuffix"}]',
    )
    # Forward PII_SAFE_REGEX_LIST to the PII-Shield sidecar via env var
    # (v1.2.0+ reads this to bypass entropy checks for whitelisted patterns)
    os.environ["PII_SAFE_REGEX_LIST"] = pii_safe_regex_list
    pii_client = PIIShieldClient(
        enabled=pii_shield_enabled,
        mode=pii_shield_mode,
        endpoint=pii_shield_endpoint,
        api_key=pii_shield_api_key,
        timeout_seconds=pii_shield_timeout,
        fail_closed=pii_shield_fail_closed,
        salt_fingerprint=pii_shield_salt_fingerprint,
        safe_regex_list=pii_safe_regex_list,
    )

    # Auto-merge
    auto_merge = parse_bool(get_env("INPUT_AUTO_MERGE", "false"))
    auto_merge_method = get_env("INPUT_AUTO_MERGE_METHOD", "squash")

    # Decision policy
    decision_policy_raw = get_env("INPUT_DECISION_POLICY", "standard")
    confidence_calibrator_input = get_env("INPUT_CONFIDENCE_CALIBRATOR", "")

    # Policy and rubric locations
    workspace = Path(get_env("GITHUB_WORKSPACE", ".")).resolve()
    rubrics_dir = resolve_path(get_env("INPUT_RUBRICS_DIR", ".guardspine/rubrics"), workspace)
    risk_policy_path = resolve_path(get_env("INPUT_RISK_POLICY"), workspace)
    bundle_dir = resolve_path(get_env("INPUT_BUNDLE_DIR", ".guardspine/bundles"), workspace) or (workspace / ".guardspine" / "bundles")
    confidence_calibrator_path = resolve_path(confidence_calibrator_input, workspace)
    decision_policy = decision_policy_raw

    if decision_policy_raw not in {"standard", "strict", "advisory"}:
        resolved_policy = resolve_existing_file(
            decision_policy_raw,
            bases=[workspace],
            extensions=("", ".yaml", ".yml"),
        )
        if not resolved_policy:
            print(f"::error::Decision policy file not found: {decision_policy_raw}")
            sys.exit(1)
        decision_policy = str(resolved_policy)

    if risk_policy_path and not risk_policy_path.exists():
        print(f"::error::Risk policy file not found: {risk_policy_path}")
        sys.exit(1)
    if confidence_calibrator_input and (not confidence_calibrator_path or not confidence_calibrator_path.exists()):
        print(f"::error::Confidence calibrator file not found: {confidence_calibrator_input}")
        sys.exit(1)

    rubric_path: Optional[Path] = None
    builtin_rubrics = RiskClassifier.discover_builtin_rubrics(workspace)
    builtin_names = RiskClassifier.builtin_names(workspace)
    if rubric in builtin_rubrics:
        rubric_path = builtin_rubrics[rubric]
    elif rubric not in builtin_names:
        bases = [workspace]
        if rubrics_dir:
            bases.append(rubrics_dir)
        resolved_rubric = resolve_existing_file(
            rubric,
            bases=bases,
            extensions=("", ".yaml", ".yml"),
        )
        if not resolved_rubric:
            print(f"::error::Rubric file not found: {rubric}")
            sys.exit(1)
        rubric_path = resolved_rubric

    # GitHub context
    github_event_path = get_env("GITHUB_EVENT_PATH")
    github_repository = get_env("GITHUB_REPOSITORY")
    github_sha = get_env("GITHUB_SHA")
    github_ref = get_env("GITHUB_REF")

    if not github_token:
        print("::error::GitHub token is required")
        sys.exit(1)

    # Load event data
    with open(github_event_path) as f:
        event = json.load(f)

    # Get PR number
    pr_number = event.get("pull_request", {}).get("number")
    if not pr_number:
        if os.environ.get("STUB_DIFF_PATH"):
            pr_number = event.get("number", 1)
        else:
            print("::notice::Not a pull request event, skipping analysis")
            sys.exit(0)

    print(f"::group::GuardSpine CodeGuard Analysis")
    print(f"Repository: {github_repository}")
    print(f"PR: #{pr_number}")
    print(f"Risk threshold: {risk_threshold}")
    print(f"Rubric: {rubric}")
    print("::endgroup::")

    # Initialize GitHub client
    gh = Github(auth=Auth.Token(github_token))
    repo = gh.get_repo(github_repository)
    pr = repo.get_pull(pr_number)

    # Get diff
    print("::group::Fetching PR diff")
    raw_diff_content = fetch_pr_diff(pr)
    diff_content_for_ai = raw_diff_content
    pii_shield_result = None
    sanitization_summary: dict[str, Any] | None = None
    print(f"Diff size: {len(raw_diff_content)} bytes")

    if pii_shield_enabled:
        try:
            pii_shield_result = pii_client.sanitize_diff(raw_diff_content)
            diff_content_for_ai = pii_shield_result.sanitized_text
            sanitization_summary = _init_sanitization_summary(
                pii_shield_result,
                pii_shield_salt_fingerprint,
            )
            sanitization_summary = _record_sanitization_stage(
                sanitization_summary,
                "ai_prompt",
                pii_shield_result,
            )
            if pii_shield_result.changed:
                print(
                    f"::notice::PII-Shield redacted {pii_shield_result.redaction_count} "
                    f"match(es) for AI review input"
                )
            else:
                print("::notice::PII-Shield enabled; no redactable content detected")
        except PIIShieldError as exc:
            print(f"::error::PII-Shield failed in fail-closed mode: {exc}")
            sys.exit(1)
        except Exception as exc:
            print(f"::error::Unexpected PII-Shield error: {exc}")
            sys.exit(1)
    print("::endgroup::")

    # Analyze diff
    print("::group::Analyzing changes")
    analyzer = DiffAnalyzer(
        openai_key=openai_key,
        anthropic_key=anthropic_key,
        openrouter_key=openrouter_key,
        openrouter_model=openrouter_model,
        ollama_host=ollama_host,
        ollama_model=ollama_model,
        model_1=model_1,
        model_2=model_2,
        model_3=model_3,
        ai_review=ai_review,
    )
    # Log AI configuration for diagnostics
    print(f"AI review enabled: {ai_review}")
    configured_models = getattr(analyzer, "models", [])
    print(f"AI providers configured: {len(configured_models)}")
    for provider, model in configured_models:
        print(f"  - {provider}/{model}")
    if not configured_models:
        print("::warning::No AI providers configured (no API keys found)")

    analysis = analyzer.analyze(
        raw_diff_content,
        rubric=rubric,
        deliberate=deliberate,
        ai_diff_content=diff_content_for_ai,
    )
    analysis["raw_diff_hash"] = analysis.get("diff_hash", "")
    analysis["ai_diff_hash"] = (
        f"sha256:{hashlib.sha256(diff_content_for_ai.encode('utf-8')).hexdigest()}"
    )
    if pii_shield_result:
        analysis["pii_shield"] = pii_shield_result.to_metadata()
        analysis["sensitive_zones"] = _merge_sensitive_zones(
            analysis.get("sensitive_zones", []),
            pii_shield_result.to_sensitive_zones(),
        )
        if sanitization_summary:
            analysis["sanitization"] = dict(sanitization_summary)
    else:
        analysis["pii_shield"] = {"enabled": False}

    if confidence_calibrator_path:
        try:
            calibrator_artifact = load_artifact(confidence_calibrator_path)
            calibration_summary = annotate_analysis_with_calibration(analysis, calibrator_artifact)
            print(
                "::notice::Confidence calibrator applied "
                f"({calibration_summary.get('source', 'unknown')})"
            )
        except Exception as exc:
            print(f"::error::Failed to apply confidence calibrator: {exc}")
            sys.exit(1)
    print(f"Files changed: {analysis['files_changed']}")
    print(f"Lines added: {analysis['lines_added']}")
    print(f"Lines removed: {analysis['lines_removed']}")

    # Log AI review results
    mmr = analysis.get("multi_model_review") or {}
    models_used = mmr.get("models_used", 0)
    models_failed = mmr.get("models_failed", 0)
    model_errors = mmr.get("model_errors", [])
    tier_from_analysis = analysis.get("preliminary_tier", "?")
    print(f"Preliminary tier: {tier_from_analysis}")
    print(f"AI models used: {models_used}, failed: {models_failed}")
    if model_errors:
        for err in model_errors:
            print(f"::warning::AI model error: {err}")
    reason = mmr.get("reason")
    if reason:
        print(f"AI review note: {reason}")
    print("::endgroup::")

    # Classify risk
    print("::group::Classifying risk")
    if not workspace.exists():
        print("::error::GITHUB_WORKSPACE is not set - cannot locate repository root for rubric loading")
        sys.exit(1)
    try:
        classifier = RiskClassifier(
            rubric=rubric,
            rubric_path=rubric_path,
            policy_path=risk_policy_path,
            repo_root=workspace,
        )
    except Exception as exc:
        print(f"::error::Failed to load rubric/policy: {exc}")
        sys.exit(1)

    risk_result = classifier.classify(analysis)
    risk_tier = risk_result["risk_tier"]
    risk_drivers = risk_result["risk_drivers"]
    findings = risk_result["findings"]

    print(f"Risk tier: {risk_tier}")
    print(f"Top drivers: {json.dumps(risk_drivers[:3], indent=2)}")
    print(f"Findings: {len(findings)}")
    print("::endgroup::")

    # Risk threshold context
    tier_order = ["L0", "L1", "L2", "L3", "L4"]
    threshold_index = tier_order.index(risk_threshold)
    risk_index = tier_order.index(risk_tier)
    tier_exceeds_threshold = risk_index >= threshold_index

    # --- Decision Engine ---
    print("::group::Running Decision Engine")
    audit_findings = _map_findings(findings)
    engine = DecisionEngine(decision_policy)
    decision_packet = engine.decide(audit_findings)
    if risk_tier == "L4" and decision_packet.decision == "merge":
        print("::warning::L4 risk cannot auto-merge; forcing merge-with-conditions")
        decision_packet.decision = "merge-with-conditions"
        decision_packet.conditions = list(decision_packet.conditions) + [
            AuditFinding(
                severity="high",
                category="governance",
                location=None,
                description="L4 risk tier requires human approval before merge",
                recommendation="Require manual reviewer approval and release gate sign-off",
                provable=False,
            )
        ]
        decision_packet.total_findings = max(decision_packet.total_findings, len(audit_findings))

    requires_approval = tier_exceeds_threshold or decision_packet.decision != "merge"
    decision_card_md = render_decision_card(decision_packet)
    print(f"Decision: {decision_packet.decision}")
    print(f"Hard blocks: {len(decision_packet.hard_blocks)}")
    print(f"Conditions: {len(decision_packet.conditions)}")
    print(f"Advisory: {len(decision_packet.advisory)}")
    print("::endgroup::")

    # Set outputs
    set_output("risk_tier", risk_tier)
    set_output("risk_drivers", json.dumps(risk_drivers))
    set_output("findings_count", str(len(findings)))
    set_output("requires_approval", str(requires_approval).lower())
    set_output("decision", decision_packet.decision)

    # Multi-model outputs
    models_used = analysis.get("models_used", 0)
    consensus_risk = analysis.get("consensus_risk", "")
    agreement_score = analysis.get("agreement_score", 0.0)
    confidence_calibration = analysis.get("confidence_calibration", {})
    set_output("models_used", str(models_used))
    set_output("consensus_risk", consensus_risk)
    set_output("agreement_score", str(agreement_score))
    calibrated_confidence = confidence_calibration.get("calibrated_verdict_p_correct")
    set_output("calibrated_confidence", "" if calibrated_confidence is None else str(calibrated_confidence))
    set_output("confidence_source", confidence_calibration.get("source", ""))

    # Post PR comment (Decision Card replaces old Diff Postcard)
    if post_comment:
        print("::group::Posting PR comment")
        commenter = PRCommenter(gh, repo, pr)
        comment_body = decision_card_md
        if pii_shield_enabled and pii_shield_sanitize_comments:
            try:
                comment_result = pii_client.sanitize_text(
                    decision_card_md,
                    input_format="markdown",
                    include_findings=False,
                    purpose="pr_comment",
                )
                sanitization_summary = _record_sanitization_stage(
                    sanitization_summary,
                    "pr_comment",
                    comment_result,
                )
                comment_body = comment_result.sanitized_text
                if comment_result.changed:
                    print(
                        f"::notice::PII-Shield redacted {comment_result.redaction_count} "
                        f"match(es) in PR comment body"
                    )
            except PIIShieldError as exc:
                print(f"::error::PII-Shield failed while sanitizing PR comment: {exc}")
                sys.exit(1)
            except Exception as exc:
                print(f"::warning::PII-Shield error in comment sanitization: {exc}")
                if pii_shield_fail_closed:
                    sys.exit(1)
        try:
            commenter.post_decision_card(comment_body)
            print("Decision Card posted")
        except Exception as exc:
            print(f"::warning::Failed to post PR comment (check GITHUB_TOKEN permissions): {exc}")
            print("::warning::Ensure workflow has 'permissions: pull-requests: write'")
        print("::endgroup::")

    # Generate evidence bundle
    bundle_path = None
    if generate_bundle:
        print("::group::Generating evidence bundle")
        generator = BundleGenerator()
        if sanitization_summary:
            analysis["sanitization"] = dict(sanitization_summary)
        bundle = generator.create_bundle(
            pr=pr,
            analysis=analysis,
            risk_result=risk_result,
            repository=github_repository,
            commit_sha=github_sha
        )

        if sanitization_summary:
            bundle["sanitization"] = dict(sanitization_summary)
            if isinstance(bundle.get("analysis_snapshot"), dict):
                bundle["analysis_snapshot"]["sanitization"] = dict(sanitization_summary)

        if pii_shield_enabled and pii_shield_sanitize_bundle:
            try:
                bundle, bundle_result = pii_client.sanitize_json_document(
                    bundle,
                    purpose="evidence_bundle",
                )
                sanitization_summary = _record_sanitization_stage(
                    sanitization_summary,
                    "evidence_bundle",
                    bundle_result,
                )
                if bundle_result.changed:
                    print(
                        f"::notice::PII-Shield redacted {bundle_result.redaction_count} "
                        f"match(es) in evidence bundle"
                    )
            except PIIShieldError as exc:
                print(f"::error::PII-Shield failed while sanitizing evidence bundle: {exc}")
                sys.exit(1)
            except Exception as exc:
                print(f"::warning::PII-Shield error in bundle sanitization: {exc}")
                if pii_shield_fail_closed:
                    sys.exit(1)

        # Save bundle
        bundle_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = bundle_dir / f"bundle-pr{pr_number}-{github_sha[:7]}.json"

        with open(bundle_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(bundle, f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
            f.write("\n")

        # Output path relative to workspace so upload-artifact (which runs
        # outside the Docker container) can resolve it against the host
        # workspace directory.  Absolute container paths like
        # /github/workspace/... don't exist on the host.
        try:
            relative_bundle = bundle_path.relative_to(workspace)
        except ValueError:
            relative_bundle = bundle_path
        set_output("bundle_path", str(relative_bundle))
        print(f"Bundle saved: {relative_bundle}")
        print(f"Bundle ID: {bundle['bundle_id']}")
        print("::endgroup::")

        # Upload as artifact
        print(f"::notice::Evidence bundle generated: {relative_bundle}")

    # Upload SARIF if requested
    if upload_sarif and findings:
        print("::group::Generating SARIF report")
        exporter = SARIFExporter()
        sarif = exporter.export(findings, github_repository, github_sha)
        if pii_shield_enabled and pii_shield_sanitize_sarif:
            try:
                sarif, sarif_result = pii_client.sanitize_json_document(
                    sarif,
                    purpose="sarif",
                )
                sanitization_summary = _record_sanitization_stage(
                    sanitization_summary,
                    "sarif",
                    sarif_result,
                )
                if sarif_result.changed:
                    print(
                        f"::notice::PII-Shield redacted {sarif_result.redaction_count} "
                        f"match(es) in SARIF output"
                    )
            except PIIShieldError as exc:
                print(f"::error::PII-Shield failed while sanitizing SARIF output: {exc}")
                sys.exit(1)
            except Exception as exc:
                print(f"::warning::PII-Shield error in SARIF sanitization: {exc}")
                if pii_shield_fail_closed:
                    sys.exit(1)
        sarif_path = Path(get_env("GITHUB_WORKSPACE", ".")) / "guardspine-results.sarif"

        with open(sarif_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
            f.write("\n")

        print(f"SARIF saved: {sarif_path}")
        print("::endgroup::")

    # Determine exit status (decision engine is authoritative)
    if decision_packet.decision == "block":
        print(f"::error::Decision Engine: BLOCKED ({len(decision_packet.hard_blocks)} provable failures)")
        print(f"::error file=GUARDSPINE::Merge blocked by {len(decision_packet.hard_blocks)} provable finding(s).")
        sys.exit(1)
    elif decision_packet.decision == "merge-with-conditions":
        print(f"::warning::Decision Engine: CONDITIONAL ({len(decision_packet.conditions)} reviewer action(s) required)")
        if fail_on_high_risk:
            sys.exit(1)
    else:
        print(f"::notice::Decision Engine: MERGE - clean to merge (risk tier {risk_tier})")
        if auto_merge and risk_tier != "L4":
            bundle_id = bundle["bundle_id"] if generate_bundle and bundle_path else "none"
            _auto_merge(pr, auto_merge_method, risk_tier, bundle_id)

    sys.exit(0)


def _auto_merge(pr: PullRequest, merge_method: str, risk_tier: str, bundle_id: str) -> bool:
    """Merge the PR. Fail loud on error, don't swallow exceptions."""
    if pr.state != "open":
        print(f"::warning::PR #{pr.number} is {pr.state}, skipping merge")
        return False
    if pr.mergeable is False:
        print(f"::warning::PR #{pr.number} has conflicts, skipping merge")
        return False
    title = pr.title
    body = (f"Auto-merged by CodeGuard (risk: {risk_tier})\n\n"
            f"Evidence bundle: {bundle_id}")
    result = pr.merge(
        commit_title=title,
        commit_message=body,
        merge_method=merge_method,
        sha=pr.head.sha)
    if result.merged:
        print(f"::notice::Auto-merged PR #{pr.number} as {result.sha[:7]}")
        set_output("merged", "true")
        set_output("merge_sha", result.sha)
        return True
    print(f"::error::Merge failed: {result.message}")
    set_output("merged", "false")
    return False


def _map_findings(finding_dicts: list[dict]) -> list[AuditFinding]:
    """Map codeguard-action finding dicts to decision engine Finding objects."""
    mapped = []
    for fd in finding_dicts:
        location = None
        if fd.get("file"):
            location = fd["file"]
            if fd.get("line"):
                location += f":{fd['line']}"
        provable_value = fd.get("provable")
        if isinstance(provable_value, bool):
            provable = provable_value
        elif isinstance(provable_value, str):
            provable = parse_bool(provable_value)
        else:
            # Backward compatibility for older finding payloads.
            provable = bool(fd.get("rule_id")) and fd.get("rule_id") != "ai-consensus"
        mapped.append(AuditFinding(
            severity=fd.get("severity", "medium"),
            category=fd.get("zone", "general"),
            location=location,
            description=fd.get("message", ""),
            recommendation=f"Review {fd.get('rule_id', 'finding')}",
            provable=provable,
        ))
    return mapped


# --- Guard Lane Routing (document governance) ---

# Extension-to-lane mapping for non-code file types.
# Files not matching any lane use the default code review pipeline.
_EXTENSION_LANES: dict[str, str] = {
    ".pdf": "pdf",
    ".xlsx": "sheet",
    ".xlsm": "sheet",
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".bmp": "image",
    ".tiff": "image",
}


def detect_guard_lane(filename: str) -> Optional[str]:
    """Return the guard lane for *filename* based on its extension.

    Returns ``None`` when the file should use the default code lane.
    """
    ext = Path(filename).suffix.lower()
    return _EXTENSION_LANES.get(ext)


def group_files_by_lane(filenames: list[str]) -> dict[Optional[str], list[str]]:
    """Group *filenames* by their guard lane.

    Returns a dict keyed by lane name (or ``None`` for the default code lane).
    """
    groups: dict[Optional[str], list[str]] = {}
    for name in filenames:
        lane = detect_guard_lane(name)
        groups.setdefault(lane, []).append(name)
    return groups


def fetch_pr_diff(pr: PullRequest) -> str:
    """Fetch the diff content for a PR."""
    stub_path = os.environ.get("STUB_DIFF_PATH")
    if stub_path:
        path = Path(stub_path)
        if not path.is_absolute():
            workspace = Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve()
            path = workspace / path
        if path.exists():
            return path.read_text(encoding="utf-8")
        print(f"::error::STUB_DIFF_PATH set but file not found: {path}")
        sys.exit(1)

    import requests

    # Use the API URL (pr.url) instead of pr.diff_url (web URL).
    # The web URL (github.com/...pull/N.diff) returns 404 on private repos
    # even with a Bearer token. The API URL works for both public and private.
    diff_url = pr.url
    token = (
        os.environ.get("INPUT_GITHUB_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
    )
    headers = {
        "Accept": "application/vnd.github.diff",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    response = requests.get(diff_url, headers=headers, timeout=30)
    if response.status_code == 406:
        # Large diffs may not be available via API; fall back to per-file patches.
        print("::warning::Diff too large for single API response, fetching per-file patches")
        return _fetch_pr_diff_paginated(pr, token)
    response.raise_for_status()
    return response.text


def _fetch_pr_diff_paginated(pr, token: str | None) -> str:
    """Fetch diff by iterating over PR files when the full diff is too large."""
    import requests

    parts: list[str] = []
    page = 1
    while True:
        url = f"{pr.url}/files?per_page=100&page={page}"
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        files = resp.json()
        if not files:
            break
        for f in files:
            patch = f.get("patch", "")
            if patch:
                parts.append(f"diff --git a/{f['filename']} b/{f['filename']}\n{patch}")
        page += 1
    return "\n".join(parts)


def set_output(name: str, value: str):
    """Set GitHub Actions output."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    text = str(value)
    if output_file:
        delimiter = f"EOF_{hashlib.sha256(f'{name}:{text}'.encode()).hexdigest()[:16]}"
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(f"{name}<<{delimiter}\n")
            f.write(f"{text}\n")
            f.write(f"{delimiter}\n")
    else:
        # Legacy fallback with escaping.
        escaped = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::set-output name={name}::{escaped}")


if __name__ == "__main__":
    main()
