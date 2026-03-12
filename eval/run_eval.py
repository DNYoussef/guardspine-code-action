#!/usr/bin/env python
"""
CodeGuard Action Eval Harness v3.0

Runs diff samples through the DiffAnalyzer -> RiskClassifier -> DecisionEngine
pipeline. Supports hand-crafted samples and open-source benchmark datasets.

Usage:
    python run_eval.py                          # Auto tier, hand-crafted samples
    python run_eval.py --tier L1                # Force L1 (1 model)
    python run_eval.py --tier L0                # Rules only, no API calls
    python run_eval.py --dataset cvefixes       # Run CVEFixes benchmark
    python run_eval.py --dataset real-cve-intro # Introducing commits (forward diffs)
    python run_eval.py --dataset all            # All datasets
    python run_eval.py --sample sqli_01.patch   # Single sample
    python run_eval.py -v                       # Verbose per-sample output
"""

import argparse
import json
import os
import sys
import time
try:
    import tomllib as toml
except ImportError:
    import toml
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_EVAL = Path(__file__).resolve().parent
_MANIFEST = _EVAL / "datasets" / "real-cve-manifest.yaml"
sys.path.insert(0, str(_ROOT))

from src.analyzer import DiffAnalyzer
from src.risk_classifier import RiskClassifier
from src.decision_engine import Finding as AuditFinding, DecisionEngine, render_decision_card

# Thresholds (overridable for CI profiles)
DEFAULT_THRESHOLD_FP = float(os.environ.get("CODEGUARD_EVAL_MAX_FP", "5.0"))
DEFAULT_THRESHOLD_FN = float(os.environ.get("CODEGUARD_EVAL_MAX_FN", "5.0"))
DEFAULT_THRESHOLD_NOISE = float(os.environ.get("CODEGUARD_EVAL_MAX_NOISE", "10.0"))

TIER_MODEL_COUNT = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 3}

# ---------------------------------------------------------------------------
# Manifest (for real-cve / real-cve-intro metadata)
# ---------------------------------------------------------------------------

def load_manifest() -> dict[str, dict]:
    """Load real-cve-manifest.yaml and return a dict keyed by sanitised CVE ID filename."""
    if not _MANIFEST.exists():
        return {}
    try:
        import yaml
        data = yaml.safe_load(_MANIFEST.read_text(encoding="utf-8")) or {}
        entries = data.get("vulnerabilities", [])
    except ImportError:
        # Fallback: minimal YAML parser
        entries = _parse_manifest_fallback(_MANIFEST.read_text(encoding="utf-8"))
    lookup: dict[str, dict] = {}
    for e in entries:
        cve_id = e.get("cve_id", "")
        # filename key: cve_2024_34069.patch
        key = cve_id.lower().replace("-", "_") + ".patch"
        lookup[key] = e
    return lookup


def _parse_manifest_fallback(text: str) -> list[dict]:
    entries: list[dict] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- repo:"):
            if current:
                entries.append(current)
            current = {"repo": stripped.split(":", 1)[1].strip()}
        elif ":" in stripped and not stripped.startswith("#") and current:
            key, val = stripped.split(":", 1)
            current[key.strip().lstrip("- ")] = val.strip()
    if current:
        entries.append(current)
    return entries

# Dataset directories under eval/samples/
DATASETS = {
    "hand-crafted": "hand-crafted",
    "python-cwe": "python-cwe",
    "cvefixes": "cvefixes",
    "juliet": "juliet",
    "castle": "castle",
    "real-cve": "real-cve",
    "real-cve-intro": "real-cve-intro",
}


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class Result:
    sample: str
    dataset: str
    category: str          # vulnerable | clean | introducing (introducing excluded from scoring)
    expected_flag: bool
    tier_preliminary: str
    tier_final: str
    zones: int
    findings: int
    severities: dict[str, int]
    decision: str          # merge | merge-with-conditions | block
    models_used: int
    consensus: str
    agreement: float
    elapsed: float
    errors: list[str]
    forced_tier: str
    deliberation_rounds: int = 0
    early_exit: bool = False
    cve_id: str = ""
    introducing_reasoning: str = ""

    @property
    def flagged(self) -> bool:
        """Decision engine enforcement: block or conditions."""
        return self.decision in ("block", "merge-with-conditions")

    @property
    def ai_detected(self) -> bool:
        """AI signal: consensus is not approve (request_changes or comment)."""
        return self.consensus not in ("approve", "", None)

    @property
    def correct(self) -> bool:
        return self.flagged == self.expected_flag

    @property
    def false_positive(self) -> bool:
        return not self.expected_flag and self.flagged

    @property
    def false_negative(self) -> bool:
        return self.expected_flag and not self.flagged


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def make_analyzer(openrouter_key: str, tier: str | None) -> DiffAnalyzer:
    """Create a DiffAnalyzer configured for a specific tier."""
    if tier == "L0":
        return DiffAnalyzer(openrouter_key=openrouter_key, ai_review=False)
    return DiffAnalyzer(openrouter_key=openrouter_key, ai_review=bool(openrouter_key))


def run_sample(
    sample_path: Path,
    dataset_name: str,
    analyzer: DiffAnalyzer,
    classifier: RiskClassifier,
    engine: DecisionEngine,
    forced_tier: str | None = None,
    deliberate: bool = False,
    manifest_entry: dict | None = None,
) -> Result:
    """Run one diff sample through the full pipeline."""
    errors = []
    start = time.monotonic()

    diff_content = sample_path.read_text(encoding="utf-8")
    category = sample_path.parent.name
    expected_flag = category == "vulnerable"

    if category == "introducing":
        errors.append("EXCLUDED: introducing patches have unverified labels")

    # 1. Analyze (pass forced_tier so analyzer uses correct model count)
    try:
        analysis = analyzer.analyze(diff_content, rubric="default", tier_override=forced_tier, deliberate=deliberate)
    except Exception as e:
        errors.append(f"Analyzer: {e}")
        analysis = {
            "files_changed": 0, "lines_added": 0, "lines_removed": 0,
            "files": [], "sensitive_zones": [], "preliminary_tier": "L0",
        }

    tier_preliminary = analysis.get("preliminary_tier", "L0")

    # 2. Classify
    try:
        risk = classifier.classify(analysis)
    except Exception as e:
        errors.append(f"Classifier: {e}")
        risk = {"risk_tier": forced_tier or tier_preliminary, "findings": []}

    tier_final = risk.get("risk_tier", "L0")
    findings = risk.get("findings", [])

    # 3. Decide
    try:
        audit_findings = _map_findings(findings)
    except Exception as e:
        errors.append(f"MapFindings: {e}")
        audit_findings = []
    try:
        packet = engine.decide(audit_findings)
    except Exception as e:
        errors.append(f"DecisionEngine: {e}")
        packet = _empty_packet()

    # Severity counts
    sevs: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "medium") if isinstance(f, dict) else getattr(f, "severity", "medium")
        sevs[s] = sevs.get(s, 0) + 1

    # Surface model errors so they're visible in output
    model_errors = analysis.get("model_errors", [])
    for me in model_errors:
        errors.append(f"Model: {me}")

    # Deliberation metadata
    mmr = analysis.get("multi_model_review", {})
    delib_rounds = mmr.get("deliberation_rounds", 0)
    delib_early = mmr.get("early_exit", False)

    me_ = manifest_entry or {}
    return Result(
        sample=sample_path.name,
        dataset=dataset_name,
        category=category,
        expected_flag=expected_flag,
        tier_preliminary=tier_preliminary,
        tier_final=tier_final,
        zones=len(analysis.get("sensitive_zones", [])),
        findings=len(findings),
        severities=sevs,
        decision=packet.decision,
        models_used=analysis.get("models_used", 0) if isinstance(analysis.get("models_used"), int) else 0,
        consensus=analysis.get("consensus_risk") or "",
        agreement=analysis.get("agreement_score") or 0.0,
        elapsed=round(time.monotonic() - start, 2),
        errors=errors,
        forced_tier=forced_tier or "auto",
        deliberation_rounds=delib_rounds,
        early_exit=delib_early,
        cve_id=me_.get("cve_id", ""),
        introducing_reasoning=me_.get("introducing_reasoning", ""),
    )


def _map_findings(finding_dicts: list) -> list[AuditFinding]:
    mapped = []
    for fd in finding_dicts:
        if not isinstance(fd, dict):
            continue
        loc = fd.get("file", "")
        if fd.get("line"):
            loc += f":{fd['line']}"
        provable_value = fd.get("provable")
        if isinstance(provable_value, bool):
            provable = provable_value
        elif isinstance(provable_value, str):
            provable = provable_value.lower() in ("true", "1", "yes")
        else:
            provable = bool(fd.get("rule_id")) and fd.get("rule_id") != "ai-consensus"
        mapped.append(AuditFinding(
            severity=fd.get("severity") or "medium",
            category=fd.get("zone") or "general",
            location=loc or None,
            description=fd.get("message") or "",
            recommendation=f"Review {fd.get('rule_id') or 'finding'}",
            provable=provable,
        ))
    return mapped


class _EmptyPacket:
    decision = "merge"
    hard_blocks = []
    conditions = []
    advisory = []
    total_findings = 0

def _empty_packet():
    return _EmptyPacket()


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def compute_stats(
    results: list[Result],
    threshold_fp: float,
    threshold_fn: float,
) -> dict:
    # Exclude introducing samples from scoring -- labels are unverified
    scored = [r for r in results if r.category in ("vulnerable", "clean")]
    total = len(scored)
    if total == 0:
        return {"total": 0, "excluded_introducing": len(results) - len(scored)}

    vuln = [r for r in scored if r.expected_flag]
    clean = [r for r in scored if not r.expected_flag]

    # Decision engine metrics (block/conditions)
    fp = sum(1 for r in results if r.false_positive)
    fn = sum(1 for r in results if r.false_negative)
    correct = sum(1 for r in results if r.correct)

    detect_rate = sum(1 for r in vuln if r.flagged) / len(vuln) * 100 if vuln else 0
    fp_rate = fp / len(clean) * 100 if clean else 0
    fn_rate = fn / len(vuln) * 100 if vuln else 0

    # AI signal metrics (consensus != approve)
    ai_vuln_detected = sum(1 for r in vuln if r.ai_detected)
    ai_clean_alarmed = sum(1 for r in clean if r.ai_detected)
    ai_detect_pct = round(ai_vuln_detected / len(vuln) * 100, 1) if vuln else 0
    ai_fp_pct = round(ai_clean_alarmed / len(clean) * 100, 1) if clean else 0

    # Tier classification accuracy (how well does the classifier assign tiers)
    tier_dist = dict(Counter(r.tier_final for r in results))

    return {
        "total": total,
        "excluded_introducing": len(results) - len(scored),
        "correct": correct,
        "accuracy_pct": round(correct / total * 100, 1),
        "vuln_count": len(vuln),
        "clean_count": len(clean),
        "detect_rate_pct": round(detect_rate, 1),
        "fp": fp, "fp_rate_pct": round(fp_rate, 1),
        "fn": fn, "fn_rate_pct": round(fn_rate, 1),
        "fp_pass": fp_rate < threshold_fp,
        "fn_pass": fn_rate < threshold_fn,
        "tier_dist": tier_dist,
        # AI signal layer
        "ai_vuln_detected": ai_vuln_detected,
        "ai_detect_pct": ai_detect_pct,
        "ai_clean_alarmed": ai_clean_alarmed,
        "ai_fp_pct": ai_fp_pct,
    }


def print_report(
    results: list[Result],
    stats: dict,
    elapsed: float,
    verbose: bool,
    threshold_fp: float,
    threshold_fn: float,
):
    print("\n" + "=" * 60)
    print("EVAL SUMMARY")
    print("=" * 60)

    # Decision engine metrics
    print("Decision Engine (enforcement):")
    print(f"  Accuracy:        {stats['correct']}/{stats['total']} ({stats['accuracy_pct']}%)")
    excluded = stats.get("excluded_introducing", 0)
    if excluded:
        print(f"  Excluded:        {excluded} introducing samples (unverified labels)")
    print(f"  Detection rate:  {stats['detect_rate_pct']}% ({stats['vuln_count']} vulnerable samples)")
    print(f"  FP rate:         {stats['fp']}/{stats['clean_count']} ({stats['fp_rate_pct']}%)")
    print(f"  FN rate:         {stats['fn']}/{stats['vuln_count']} ({stats['fn_rate_pct']}%)")

    # AI signal metrics
    ai_det = stats.get("ai_vuln_detected", 0)
    ai_fp = stats.get("ai_clean_alarmed", 0)
    print()
    print("AI Signal (consensus != approve):")
    print(f"  AI detection:    {ai_det}/{stats['vuln_count']} ({stats.get('ai_detect_pct', 0)}%)")
    print(f"  AI false alarm:  {ai_fp}/{stats['clean_count']} ({stats.get('ai_fp_pct', 0)}%)")

    print()
    print(f"Time:            {elapsed:.1f}s")

    print()
    fp_ok = "PASS" if stats["fp_pass"] else "FAIL"
    fn_ok = "PASS" if stats["fn_pass"] else "FAIL"
    print(f"Threshold FP (<{threshold_fp}%): {fp_ok} ({stats['fp_rate_pct']}%)")
    print(f"Threshold FN (<{threshold_fn}%): {fn_ok} ({stats['fn_rate_pct']}%)")

    # Tier distribution
    print()
    print("Tier distribution:")
    for tier in sorted(stats["tier_dist"]):
        print(f"  {tier}: {stats['tier_dist'][tier]}")

    # Per-sample tier detail (verbose only)
    if verbose:
        print()
        print("Per-sample tier assignments:")
        for r in results:
            flag_icon = "!" if r.flagged else " "
            ai_icon = "~" if r.ai_detected else " "
            print(f"  [{flag_icon}{ai_icon}] {r.tier_preliminary}->{r.tier_final}  {r.category:10s}  {r.sample}")

    # By category
    print()
    for cat in ("vulnerable", "clean"):
        cat_r = [r for r in results if r.category == cat]
        cat_ok = sum(1 for r in cat_r if r.correct)
        print(f"  {cat:12s}: {cat_ok}/{len(cat_r)}")

    # By dataset
    datasets = sorted(set(r.dataset for r in results))
    if len(datasets) > 1:
        print()
        for ds in datasets:
            ds_r = [r for r in results if r.dataset == ds]
            ds_stats = compute_stats(ds_r, threshold_fp, threshold_fn)
            print(f"  {ds:16s}: {ds_stats['accuracy_pct']}% acc, FP={ds_stats['fp_rate_pct']}%, FN={ds_stats['fn_rate_pct']}%")

    # Failures
    failures = [r for r in results if not r.correct]
    if failures and verbose:
        print()
        print("FAILURES:")
        for r in failures:
            label = "FP" if r.false_positive else "FN"
            ai_note = f" [AI: {r.consensus}]" if r.consensus else ""
            print(f"  [{label}] {r.dataset}/{r.category}/{r.sample} -> {r.decision}{ai_note}")


def write_results(
    results: list[Result],
    stats: dict,
    forced_tier: str | None,
    elapsed: float,
    threshold_fp: float,
    threshold_fn: float,
    threshold_noise: float,
):
    results_dir = _EVAL / "results"
    results_dir.mkdir(exist_ok=True)

    ts = time.strftime("%Y%m%d-%H%M%S")
    tier_label = forced_tier or "auto"
    out_path = results_dir / f"eval-{tier_label}-{ts}.json"

    output = {
        "meta": {
            "timestamp": ts,
            "forced_tier": forced_tier,
            "thresholds": {"fp": threshold_fp, "fn": threshold_fn, "noise": threshold_noise},
            **stats,
        },
        "results": [asdict(r) for r in results],
    }

    out_path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    print(f"\nResults: {out_path}")
    return out_path


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_api_key() -> str:
    # Project-specific secrets take priority over env var
    secrets_path = _EVAL / ".codeguard" / ".secrets.toml"
    if secrets_path.exists():
        with open(secrets_path, "rb") as f:
            data = toml.load(f)
        key = data.get("openrouter_api_key", "")
        if key:
            return key
    return os.environ.get("OPENROUTER_API_KEY", "")


def collect_samples(samples_dir: Path, dataset: str, sample_filter: str | None) -> list[tuple[Path, str]]:
    """Return list of (path, dataset_name) tuples."""
    pairs = []

    if sample_filter:
        matches = list(samples_dir.rglob(sample_filter))
        if not matches:
            print(f"ERROR: Sample not found: {sample_filter}")
            sys.exit(1)
        for m in matches:
            ds = _guess_dataset(m, samples_dir)
            pairs.append((m, ds))
        return pairs

    if dataset == "all":
        target_dirs = [samples_dir]
    elif dataset in DATASETS:
        d = samples_dir / DATASETS[dataset]
        if not d.exists():
            print(f"ERROR: Dataset dir not found: {d}")
            print(f"  Run: python eval/datasets/fetch_{dataset}.py")
            sys.exit(1)
        target_dirs = [d]
    else:
        print(f"ERROR: Unknown dataset: {dataset}")
        print(f"  Available: {', '.join(DATASETS)} or 'all'")
        sys.exit(1)

    for d in target_dirs:
        for p in sorted(d.rglob("*.patch")):
            ds = _guess_dataset(p, samples_dir)
            pairs.append((p, ds))

    return pairs


def _guess_dataset(path: Path, samples_dir: Path) -> str:
    try:
        rel = path.relative_to(samples_dir)
        first_part = rel.parts[0] if rel.parts else "unknown"
        if first_part in ("vulnerable", "clean"):
            return "hand-crafted"
        return first_part
    except ValueError:
        return "unknown"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="CodeGuard Action Eval Harness v3.0")
    p.add_argument("--tier", choices=["L0", "L1", "L2", "L3"], default=None,
                    help="Force a specific tier (default: auto)")
    p.add_argument("--dry-run", action="store_const", const="L0", dest="tier",
                    help="Alias for --tier L0 (rules only)")
    p.add_argument("--dataset", default="hand-crafted",
                    help="Dataset to run: hand-crafted, cvefixes, juliet, castle, real-cve, real-cve-intro, all")
    p.add_argument("--sample", default=None,
                    help="Run a single sample by filename")
    p.add_argument("--deliberate", action="store_true",
                    help="Enable multi-round deliberation (cross-checking between models)")
    p.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose per-sample output")
    p.add_argument("--max-fp", type=float, default=DEFAULT_THRESHOLD_FP,
                    help="Fail if false-positive rate is >= this percentage")
    p.add_argument("--max-fn", type=float, default=DEFAULT_THRESHOLD_FN,
                    help="Fail if false-negative rate is >= this percentage")
    p.add_argument("--max-noise", type=float, default=DEFAULT_THRESHOLD_NOISE,
                    help="Reserved threshold for future noise metrics")
    return p.parse_args()


def _preflight_api_key(api_key: str, tier: str | None) -> bool:
    """Check API key has credits before running L1+ evals."""
    if not tier or tier == "L0" or not api_key:
        return True
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/auth/key",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())["data"]
        usage = data.get("usage", 0)
        limit = data.get("limit")
        remaining = data.get("limit_remaining")
        print(f"OpenRouter usage: ${usage:.2f}", end="")
        if limit is not None:
            print(f"  limit: ${limit:.2f}  remaining: ${remaining:.2f}")
            if remaining is not None and remaining <= 0:
                print("ERROR: OpenRouter key has no remaining credits.")
                print("  Raise the per-key limit at https://openrouter.ai/settings/keys")
                return False
        else:
            print("  (no per-key limit)")
        return True
    except Exception as e:
        print(f"WARNING: Could not verify API key: {e}")
        return True  # proceed anyway, let the model call fail naturally


def main():
    args = parse_args()

    print("CodeGuard Action Eval Harness v3.0")
    print("=" * 60)

    # API key
    api_key = load_api_key()
    print(f"OpenRouter key: {'set' if api_key else 'MISSING'}")

    # Pre-flight: verify key has credits for L1+
    if not _preflight_api_key(api_key, args.tier):
        sys.exit(1)

    # Components
    analyzer = make_analyzer(api_key, args.tier)
    classifier = RiskClassifier(rubric="default")
    engine = DecisionEngine(policy="standard")

    print(f"Models: {len(analyzer.models)}")
    print(f"Tier:   {args.tier or 'auto'}")

    # Samples
    samples_dir = _EVAL / "samples"
    samples = collect_samples(samples_dir, args.dataset, args.sample)
    print(f"Samples: {len(samples)} ({args.dataset})")
    print("=" * 60)

    # Load manifest for real-cve / real-cve-intro metadata
    manifest = load_manifest() if args.dataset in ("real-cve", "real-cve-intro", "all") else {}

    # Run
    results = []
    t0 = time.monotonic()

    for i, (path, ds_name) in enumerate(samples, 1):
        try:
            rel = path.relative_to(samples_dir)
        except ValueError:
            rel = path.name
        print(f"\n[{i}/{len(samples)}] {rel}")

        manifest_entry = manifest.get(path.name)
        r = run_sample(path, ds_name, analyzer, classifier, engine, args.tier, args.deliberate, manifest_entry)
        results.append(r)

        label = "OK" if r.correct else ("FP" if r.false_positive else "FN")
        print(f"  {r.tier_preliminary}->{r.tier_final}  zones={r.zones}  findings={r.findings}  "
              f"decision={r.decision}  [{label}]")
        if r.models_used > 0 or any("Model:" in e for e in r.errors):
            failed = sum(1 for e in r.errors if e.startswith("Model:"))
            delib_info = ""
            if r.deliberation_rounds:
                delib_info = f"  rounds={r.deliberation_rounds}"
                if r.early_exit:
                    delib_info += " (early-exit)"
            print(f"  AI: {r.models_used} ok, {failed} failed  consensus={r.consensus or '(none)'}  agreement={r.agreement:.2f}{delib_info}")
        if r.cve_id:
            print(f"  CVE: {r.cve_id}")
            if r.introducing_reasoning and args.verbose:
                print(f"  Intro: {r.introducing_reasoning}")
        if r.errors:
            for e in r.errors:
                print(f"  ERROR: {e}")

    elapsed = time.monotonic() - t0

    # Report
    stats = compute_stats(results, args.max_fp, args.max_fn)
    print_report(results, stats, elapsed, args.verbose, args.max_fp, args.max_fn)
    write_results(results, stats, args.tier, elapsed, args.max_fp, args.max_fn, args.max_noise)

    # Exit code
    passed = stats.get("fp_pass", False) and stats.get("fn_pass", False)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
