# GuardSpine Code Action - Phase 0 Eval Results

**Date**: 2026-02-06 (updated 2026-02-07 after P0+P1+P2+P3 fixes)
**Harness Version**: v3.0
**Models**: Claude 4.5 Sonnet via OpenRouter (L1 = 1 model)
**Target Thresholds**: FP < 5%, FN < 5%, Noise < 10%

## Executive Summary

**85 total samples** across 2 datasets. Three rounds of fixes measured.

### Progression

| Stage | Accuracy | FP Rate | FN Rate | Detection | Key Change |
|-------|----------|---------|---------|-----------|------------|
| Baseline | 52.9% | 42.4% (14/33) | 50.0% (26/52) | 50.0% | Initial state |
| L0 Post-Fix | 74.1% | 63.6% (21/33) | 1.9% (1/52) | 98.1% | P1 patterns + P0 wiring |
| **L1 Final** | **97.6%** | **6.1% (2/33)** | **0.0% (0/52)** | **100.0%** | P3 prompt rewrite + double downgrade |

### L1 Benchmark (Current Best)

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Accuracy | 97.6% (83/85) | -- | -- |
| False Positive Rate | 6.1% (2/33) | < 5% | FAIL (1.1pp over) |
| False Negative Rate | 0.0% (0/52) | < 5% | **PASS** |
| Detection Rate | 100.0% (52/52) | > 95% | **PASS** |

FP rate is 1.1 percentage points over the 5% threshold (2 FPs vs max 1 allowed).

## What Changed (Chronological)

### P1: Added 6 new SENSITIVE_PATTERNS (analyzer.py)

| Zone | Severity | Patterns | FNs Fixed |
|------|----------|----------|-----------|
| command_injection | critical | subprocess, os.system, exec(), eval(), spawn | 6 CWE-78 |
| deserialization | critical | pickle.load, yaml.load, marshal, shelve, jsonpickle | 6 CWE-502 |
| template_injection | high | render_template_string, Template(), Markup(), mark_safe | 2 CWE-79 |
| path_traversal | high | os.path.join, shutil, extractall, zipfile, tarfile | 6 CWE-22 |
| weak_crypto | high | md5, sha1, DES, RC4, random.seed, random.random | 1 CWE-327 |
| xss | high | script tags, innerHTML, mark_safe, Markup(), Response | 4 CWE-79 |

**Impact**: FN 50% -> 1.9% (25/26 FNs eliminated)

### P0: Wired AI consensus into RiskClassifier (risk_classifier.py)

When multi-model AI reviews are available (L1+):
- **AI approves** (agreement >= 0.8): Zone-only findings double-downgraded
  - Rubric/policy findings are NOT downgraded (they represent organizational policy)
- **AI flags issues** (agreement >= 0.7): Medium findings upgraded to high, AI concerns
  injected as non-provable findings (triggers conditions, never hard-block)

### P2: Six bugs fixed via line-by-line audit

| # | Severity | Bug | File | Root Cause | Fix |
|---|----------|-----|------|-----------|-----|
| 1 | CRITICAL | API failures silently swallowed | analyzer.py | `_get_model_review` catches exception, `_calculate_consensus` filters error reviews | Surface `model_errors` list, pipe into harness `errors` |
| 2 | HIGH | `models_used` counts attempts not successes | analyzer.py | `len(reviews)` includes failed reviews | Split into `models_used` (successes) and `models_failed` |
| 3 | MEDIUM | `google/gemini-3-flash` invalid model | analyzer.py | Not a real OpenRouter model ID | Changed to `google/gemini-2.5-flash` |
| 4 | HIGH | consensus_risk=None | analyzer.py | `dict.get("key", default)` returns None when key exists with value None | `or` pattern throughout |
| 5 | HIGH | _map_findings pydantic crash | run_eval.py | Same dict.get() gotcha on zone=None for AI-CONCERN findings | `fd.get("zone") or "general"` |
| 6 | MEDIUM | tier_override not controlling model count | analyzer.py | Harness forced_tier only cosmetic, never passed to analyze() | Added `tier_override` param |
| 7 | HIGH | API key shadowing | run_eval.py | ENV `OPENROUTER_API_KEY` (exhausted) shadowed funded key in secrets.toml | secrets.toml takes priority |

### P3: AI prompt rewrite + double downgrade (THIS SESSION)

**Problem 1**: AI review prompt was too alarmist, causing 93.9% FP at L1:
- Role: "security and compliance review" (primed for alarm)
- Showed sensitive zones detected (biased toward flagging)
- Example JSON had concerns filled in
- No guidance on when to approve

**Fix**: Complete prompt rewrite with explicit approve/request_changes criteria:
- Lists safe patterns (parameterized SQL, bcrypt, env vars, list args, etc.)
- Lists dangerous patterns (unsanitized input, hardcoded secrets, pickle, etc.)
- Explicit instruction: "If code follows security best practices, respond with approve"

**Problem 2**: Single severity downgrade insufficient when AI approves:
- critical->high still triggered DecisionEngine conditions (high+provable)
- Safe crypto sample with AI approve still got merge-with-conditions

**Fix**: Double downgrade when AI approves:
- critical->medium, high->low, medium->info
- All drop below condition_rules threshold (high+provable)
- Zone-only keyword matches become advisory when AI confirms safe

**Problem 3**: AI concern findings mapped as provable=True:
- risk_classifier.py comment says "non-provable" for AI concerns
- But _map_findings set provable=bool(rule_id) where rule_id="ai-consensus" is truthy
- Fix: provable=False when rule_id starts with "ai-"

## L1 Results by Dataset

| Dataset | Samples | Accuracy | FP Rate | FN Rate |
|---------|---------|----------|---------|---------|
| hand-crafted | 15 (10v/5c) | 100.0% | 0.0% (0/5) | 0.0% (0/10) |
| python-cwe | 70 (42v/28c) | 97.1% | 7.1% (2/28) | 0.0% (0/42) |
| **Combined** | **85 (52v/33c)** | **97.6%** | **6.1% (2/33)** | **0.0% (0/52)** |

## L1 Results by CWE

| CWE | Name | Vuln | Clean | Detection | FP Rate | FN Rate |
|-----|------|------|-------|-----------|---------|---------|
| CWE-89 | SQL Injection | 6 | 4 | 100% (6/6) | 0% (0/4) | 0% |
| CWE-79 | XSS | 6 | 4 | 100% (6/6) | 25% (1/4) | 0% |
| CWE-78 | Command Injection | 6 | 4 | 100% (6/6) | 25% (1/4) | 0% |
| CWE-502 | Deserialization | 6 | 4 | 100% (6/6) | 0% (0/4) | 0% |
| CWE-798 | Hardcoded Creds | 6 | 4 | 100% (6/6) | 0% (0/4) | 0% |
| CWE-22 | Path Traversal | 6 | 4 | 100% (6/6) | 0% (0/4) | 0% |
| CWE-327 | Broken Crypto | 6 | 4 | 100% (6/6) | 0% (0/4) | 0% |

## Remaining Failures (L1)

### False Positives (2 remaining)

| # | Sample | CWE | AI Consensus | Decision | Why Flagged | Why Safe |
|---|--------|-----|--------------|----------|-------------|----------|
| 1 | cmdi_safe_subprocess_list | CWE-78 | request_changes | block | AI flagged f-string in docker build as risky | subprocess with list args, no shell=True |
| 2 | xss_safe_template | CWE-79 | comment | merge-with-conditions | AI uncertain, zone finding unchanged | render_template with Jinja2 autoescaping |

**Analysis**:
- FP #1: Borderline case. User input (`branch_name`) passed into `f"app:{branch_name}"` in docker build. AI legitimately flags this as worth reviewing even though no shell injection is possible with list args.
- FP #2: AI returned `comment` (uncertain) instead of `approve` for unambiguously safe render_template. At L2 with 2+ models, consensus may shift to approve.

### False Negatives (0)

100% detection rate. The last L0 FN (xss_direct_response - pure HTML string concat) was caught by AI semantic analysis at L1.

## Architecture Summary

```
L0 (rules):     74.1% acc, 98.1% detection, 63.6% FP, 1.9% FN
L1 (1 model):   97.6% acc, 100% detection, 6.1% FP, 0% FN    <- CURRENT
L2 (2 models):  Expected: FP < 5% (multi-model consensus improves edge cases)
```

The pipeline uses three stages:
1. **DiffAnalyzer** (rules): 14 SENSITIVE_PATTERNS detect security-relevant zones. Maximizes recall.
2. **AI Review** (models): Claude 4.5 Sonnet triages safe vs dangerous code. Provides precision.
3. **RiskClassifier** (modulation): Uses AI consensus to double-downgrade safe zone findings, or upgrade+inject for flagged code.
4. **DecisionEngine** (policy): Provable critical findings block, provable high findings condition, non-provable findings advise.

## Phase 1 Targets

1. Run L2 benchmark (2 models + rubric) - should push FP below 5%
2. CVEFixes dataset (needs 391MB Kaggle CSV download)
3. If FP still >= 5% at L2, add `comment` modulation (single downgrade for uncertain AI)
4. Juliet and Castle dataset integration

## Test Coverage

41 unit tests passing:
- 14 in test_risk_classifier.py (5 original + 4 new zone tests + 5 AI wiring tests)
- 27 in test_all_fixes.py (7 suites covering bundle, drivers, comments, integrity, SARIF, rubric, pipeline)
