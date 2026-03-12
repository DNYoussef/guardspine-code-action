# GuardSpine CodeGuard

**AI-powered code governance with cryptographically verifiable evidence bundles**

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-GuardSpine%20CodeGuard-blue?logo=github)](https://github.com/marketplace/actions/guardspine-codeguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

> **New here?** Start with the [5-Minute Quick Start](docs/QUICKSTART.md) -- one workflow file, one API key, done.

## The Problem

GitHub shows *that* someone clicked "Approve."
GuardSpine proves *what* they reviewed.

When an auditor asks "How did this payment logic change get approved?", GitHub gives you a green checkmark. GuardSpine gives you:
- The exact diff they saw
- The risk tier at approval time
- Cryptographic proof nothing changed after review
- A hash-chained evidence bundle you can verify independently

## Install (1 minute)

**1. Add secrets** (pick any AI provider, or skip for rules-only mode):

| Secret | Required | Notes |
|--------|----------|-------|
| `GITHUB_TOKEN` | Auto | Provided by GitHub Actions automatically |
| `OPENROUTER_API_KEY` | Pick one | Recommended - single key, 100+ models |
| `ANTHROPIC_API_KEY` | Pick one | Direct Claude access |
| `OPENAI_API_KEY` | Pick one | Direct GPT access |
| `PII_SHIELD_API_KEY` | Optional | Enable [PII-Shield](#pii-shield-integration) secret redaction |

Ollama requires no API key (self-hosted, air-gapped).

**2. Create `.github/workflows/codeguard.yml`:**

```yaml
name: CodeGuard
on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DNYoussef/codeguard-action@v1
        id: guard
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
          risk_threshold: L3
          # PII-Shield: strip secrets from AI prompts & evidence bundles
          pii_shield_enabled: true
          pii_shield_endpoint: ${{ vars.PII_SHIELD_ENDPOINT }}  # or omit for local mode
        env:
          PII_SHIELD_API_KEY: ${{ secrets.PII_SHIELD_API_KEY }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: evidence-bundle
          path: .guardspine/bundles/
```

**3. Open a PR.** You will see a Decision Card comment with the verdict (merge / merge-with-conditions / block), risk tier, and findings. The evidence bundle appears in workflow artifacts.

**Verify a bundle locally** (optional):
```bash
pip install guardspine-verify && guardspine-verify .guardspine/bundles/*.json
```

> **Troubleshooting**: Missing artifact? Ensure `bundle_dir` matches upload path. Hard fail on L4? Set `fail_on_high_risk: false` (default). No AI review? Provide at least one API key and set `ai_review: true` (default). PII-Shield failing? Check endpoint connectivity or set `pii_shield_fail_closed: false` for advisory mode.

---

## Architecture

```
PR opened/updated
       |
       v
1. DIFF ANALYSIS
   Parse unified diff, extract file changes and hunks.
   Detect sensitive zones: auth, payment, crypto, database,
   security, pii, config, infra, xss, command_injection,
   deserialization, template_injection, path_traversal, weak_crypto.
   Generate SHA-256 diff hash for integrity.
       |
       v
2. TIER-BASED MULTI-MODEL AI REVIEW
   Models scale with risk tier (not fallback -- actual multi-review):
     L0 (Trivial)  -> 0 models (rules-only, no AI)
     L1 (Low)      -> 1 model
     L2 (Medium)   -> 2 models + rubric scoring
     L3 (High)     -> 3 models + rubric scoring
     L4 (Critical) -> 3 models + rubric scoring + human approval
   Models run in parallel. Consensus: majority vote + rubric aggregation.
       |
       v
3. RISK CLASSIFICATION
   Three scoring dimensions:
     - File patterns (auth/payment/pii path matching)
     - Sensitive zones (keyword detection in diff content)
     - Change size (lines added + removed)
   Final tier = max(scores), boosted by rubric/zone findings.
   AI consensus modulates severity: approve -> downgrade zone findings,
   request_changes -> upgrade medium findings to high.
       |
       v
4. DECISION ENGINE
   Findings in, one verdict out: merge, merge-with-conditions, or block.
   Provable findings (deterministic detections) can hard-block.
   Opinion findings (AI-generated) are advisory-only -- they can trigger
   merge-with-conditions but never block.
   Policy profiles control which severities block vs. condition.
       |
       v
5. EVIDENCE BUNDLE
   Hash-chained event sequence (guardspine-spec v0.2.0):
     PR Submitted -> Analysis Complete -> Risk Classified -> Approval (if L3+)
   Supports Ed25519, RSA, ECDSA, or HMAC-SHA256 signatures.
       |
       v
6. OUTPUTS
   - Decision Card (PR comment): verdict, risk tier, findings, conditions
   - Evidence Bundle (JSON artifact): hash chain, event log, signatures
   - SARIF (optional): findings as GitHub Security alerts
```

---

## Decision Engine

The decision engine is the core of CodeGuard. It collapses all findings into exactly one of three verdicts:

| Verdict | Meaning | When |
|---------|---------|------|
| **merge** | Safe to merge | No hard blocks, no conditions |
| **merge-with-conditions** | Reviewer action needed on 1-2 items | High/critical non-provable findings present |
| **block** | Cannot merge | Provable critical finding detected |

### Provable vs. Opinion Findings

This distinction is fundamental to the decision engine:

- **Provable findings** come from deterministic detection: regex-matched sensitive zones, rubric rule pattern matches, file path classification. These are reproducible -- run the same diff twice, get the same findings. Provable findings can hard-block a PR.

- **Opinion findings** come from AI model reviews. They are non-deterministic and model-dependent. Opinion findings can only trigger `merge-with-conditions` (surfaced for human review), never `block`. This prevents AI hallucinations from blocking merges.

### Decision Policies

Three built-in policies control how findings map to verdicts. Set via `decision_policy` input.

**standard** (default): Block only on provable critical findings. Non-provable criticals and all high-severity findings become conditions (max 2).

**strict**: Block on any critical (provable or not) and on provable high-severity findings. Non-provable highs and provable mediums become conditions.

**advisory**: Never auto-block. All criticals and highs become conditions. Use this when ramping up trust in the system.

Custom policies are YAML files with three keys: `hard_block_rules`, `condition_rules`, `max_conditions`. See `src/decision_profiles/` for examples.

### AI Consensus Modulation

When AI models review the diff, their consensus adjusts finding severity before the decision engine runs:

- **AI approves (agreement >= 0.6)**: Zone-based findings are double-downgraded (critical -> high, high -> low). This reduces false positives from keyword matches the AI confirmed as benign. Rubric findings are never downgraded.
- **AI requests changes (agreement >= 0.6)**: Medium findings are upgraded to high. AI concerns are injected as non-provable high-severity findings.
- **AI comments (uncertain)**: Zone findings are single-downgraded. AI concerns are injected as medium-severity.
- **AI minority dissent**: Concerns from a single dissenting model are injected as medium-severity advisory items.

---

## Dependencies

Runtime dependencies (`requirements.txt`):

| Package | Purpose |
|---------|---------|
| `PyGithub>=2.1.0` | GitHub API for PR operations |
| `requests>=2.31.0` | HTTP client |
| `pyyaml>=6.0` | YAML parsing for rubrics and policies |
| `unidiff>=0.7.5` | Unified diff parsing |
| `cryptography>=41.0` | Bundle signing (Ed25519, RSA, ECDSA) |
| `guardspine-kernel>=0.2.0` | Evidence bundle types and canonical JSON |
| `openai>=1.0.0` | OpenAI/OpenRouter API adapter |
| `anthropic>=0.18.0` | Anthropic API adapter |
| `wasmtime>=16.0.0` | WASM runtime for PII-Shield local mode |
| `toml==0.10.2` | TOML parsing |

The decision engine (`src/decision_engine.py`) is vendored from `guardspine-product`. It is kept vendored because the Docker image runs without access to private pip indexes. The provenance header in the file tracks the sync date. Re-sync manually when the upstream decision logic changes.

---

### Risk Tiers

| Tier | Label | AI Models | Rubric | Description | Default Action |
|------|-------|-----------|--------|-------------|----------------|
| **L0** | Trivial | 0 (none) | No | Docs, comments, formatting | Auto-approve |
| **L1** | Low | 1 | No | Tests, non-critical code | Auto-approve |
| **L2** | Medium | 2 | Yes | Feature code, minor changes | Auto-approve |
| **L3** | High | 3 | Yes | Auth, config, sensitive areas | Requires approval |
| **L4** | Critical | 3 | Yes | Payments, PII, security, crypto | Requires HUMAN approval |

---

### Diff Analysis Output

![CodeGuard Diff Analysis](docs/diff-analysis-demo.png)

*Sensitive zones automatically detected in auth and payment code with risk tier assignment*

---

## Features

### Decision Card (PR Comment)

Every PR gets a decision card comment showing:
- Verdict: merge, merge-with-conditions, or block
- Risk tier with rationale
- Hard blocks (provable failures that prevent merge)
- Conditions (max 2 items requiring reviewer action)
- Advisory findings (collapsed, informational)

### Evidence Bundles

Cryptographically verifiable JSON bundles following [guardspine-spec](https://github.com/DNYoussef/guardspine-spec) v0.2.0. Contains:
- Hash-chained event sequence (tamper-evident)
- v0.2.0 `items` + `immutability_proof` (canonical)
- Legacy `events` + `hash_chain` (backward compatible, will be removed in next major)
- Diff snapshot at analysis time
- Risk assessment details
- Approval records (when applicable)
- Optional cryptographic signatures

Verify any bundle independently -- see [Verification](#verification) section below.

### Compliance Rubrics

Pre-built rubric YAML files ship in `rubrics/builtin/`:

| Rubric | File | Purpose |
|--------|------|---------|
| default | `default.yaml` | General code quality |
| security | `security.yaml` | Security-focused patterns |
| soc2 | `soc2-controls.yaml` | SOC 2 CC6/CC7/CC8 evidence mapping |
| hipaa | `hipaa-safeguards.yaml` | HIPAA 164.312 safeguard documentation |
| pci-dss | `pci-dss-requirements.yaml` | PCI-DSS Req 3/6/8 evidence |
| connascence | `connascence.yaml` | Coupling analysis |
| safety-violations | `safety-violations.yaml` | Safety-critical code patterns |
| nasa-safety | `nasa-safety.yaml` | NASA Power of Ten rules |
| theater-detection | `theater-detection.yaml` | Security theater detection |

Custom rubrics are YAML files with a `rules` key. Place them in `.guardspine/rubrics/` or pass a path via the `rubric` input. Rules support `pattern`/`patterns` (regex), `severity`, `message`, and `exceptions` (glob patterns to skip).

> **Note**: These are *evidence mappings* that help document your existing controls -- they do not make you compliant by themselves. Always work with your auditors.

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    rubric: hipaa  # or: soc2, pci-dss, default, security, or path to custom YAML
```

### SARIF Integration

Export findings to GitHub Security tab:

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    upload_sarif: true

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: guardspine-results.sarif
```

### Auto-Merge

Clean PRs (decision=merge, tier below threshold) can be auto-merged:

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    auto_merge: true
    auto_merge_method: squash  # or merge, rebase
```

Requires `contents: write` permission on the workflow.

## Configuration

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `risk_threshold` | Tier at which to require approval (L0-L4) | `L3` |
| `rubric` | Policy rubric (default, security, soc2, hipaa, pci-dss, or custom YAML path) | `default` |
| `github_token` | GitHub token for PR operations | Required |
| `post_comment` | Post Decision Card comment | `true` |
| `generate_bundle` | Create evidence bundle artifact | `true` |
| `upload_sarif` | Upload to GitHub Security tab | `false` |
| `fail_on_high_risk` | Block merge if over threshold (exit 1) | `false` |
| `rubrics_dir` | Directory containing rubric YAML files | `.guardspine/rubrics` |
| `risk_policy` | Path to YAML that overrides risk patterns/thresholds | - |
| `bundle_dir` | Directory to write evidence bundles | `.guardspine/bundles` |
| `decision_policy` | Decision engine policy: standard, strict, advisory, or path to custom YAML | `standard` |
| `deliberate` | Enable deliberation (multi-round cross-checking between AI models) | `false` |
| `auto_merge` | Auto-merge clean PRs (decision=merge, tier below threshold) | `false` |
| `auto_merge_method` | Merge method: merge, squash, or rebase | `squash` |
| **Model Configuration** | | |
| `model_1` | First model (L1+). Format: `provider/model` or just `model` | Auto-detect |
| `model_2` | Second model (L2+). Format: `provider/model` or just `model` | Auto-detect |
| `model_3` | Third model (L3+). Format: `provider/model` or just `model` | Auto-detect |
| `ai_review` | Enable AI-powered code review | `true` |
| **API Keys** | | |
| `openai_api_key` | OpenAI key for GPT models (optional) | - |
| `anthropic_api_key` | Anthropic key for Claude models (optional) | - |
| `openrouter_api_key` | OpenRouter key (access 100+ models) (optional) | - |
| `ollama_host` | Ollama server URL for local AI (optional) | - |
| `guardspine_api_url` | GuardSpine backend URL for dashboard sync and Slack alerts | - |
| `guardspine_api_key` | GuardSpine service API key for backend auth | - |

### Outputs

| Output | Description |
|--------|-------------|
| `risk_tier` | Assessed risk tier (L0-L4) |
| `risk_drivers` | JSON array of top risk drivers |
| `bundle_path` | Path to evidence bundle |
| `findings_count` | Number of policy findings |
| `requires_approval` | Whether approval needed (true/false) |
| `models_used` | Number of AI models that reviewed |
| `consensus_risk` | Multi-model consensus: approve/request_changes/comment |
| `agreement_score` | How much models agreed (0.0-1.0) |
| `decision` | Decision engine verdict: merge, merge-with-conditions, or block |
| `merged` | Whether PR was auto-merged |
| `merge_sha` | Merge commit SHA (if merged) |

## Advanced Usage

### Custom Risk Threshold per Branch

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    risk_threshold: ${{ github.base_ref == 'main' && 'L2' || 'L3' }}
```

### Custom Decision Policy

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    decision_policy: strict  # or: advisory, standard, path/to/custom.yaml
```

### Custom Risk Policy

Override file patterns, zone severities, or size thresholds with a YAML file:

```yaml
# .guardspine/risk-policy.yaml
file_patterns:
  L4:
    - payment
    - billing
    - hipaa
zone_severity:
  payment: critical
  auth: critical
size_thresholds:
  large: 1000
  medium: 200
  small: 50
```

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    risk_policy: .guardspine/risk-policy.yaml
```

### Multi-Model AI Configuration

Configure up to 3 AI models for tier-based review. Models are used based on risk tier (L1: 1 model, L2: 2 models, L3+: 3 models).

#### Option 1: OpenRouter (Recommended - 3 diverse models via single API)

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
    model_1: anthropic/claude-sonnet-4.5   # Used for L1+
    model_2: openai/gpt-5.2                 # Used for L2+
    model_3: google/gemini-3-flash          # Used for L3+
```

#### Option 2: Ollama (Air-Gapped - 3 local models)

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    ollama_host: http://localhost:11434
    model_1: llama4
    model_2: mistral-large
    model_3: codellama-70b
```

#### Option 3: Mixed Providers (diversity of opinion)

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    ollama_host: http://localhost:11434
    model_1: claude-haiku-4-5-20251001  # Uses Anthropic
    model_2: gpt-4.1-mini               # Uses OpenAI
    model_3: llama4                      # Uses Ollama
```

#### Option 4: Single Provider (legacy/simple)

Just provide one API key -- CodeGuard will use default models:

```yaml
# Anthropic only (uses Claude Haiku 4.5 for all tiers)
- uses: DNYoussef/codeguard-action@v1
  with:
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}

# OpenAI only (uses GPT 4.1 Mini for all tiers)
- uses: DNYoussef/codeguard-action@v1
  with:
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

| Provider | Data Residency | Best For |
|----------|----------------|----------|
| **Ollama** | Your infrastructure | Air-gapped/regulated environments |
| **OpenRouter** | OpenRouter servers | Flexibility, model diversity |
| **Anthropic** | Anthropic servers | Direct Claude access |
| **OpenAI** | OpenAI servers | Existing OpenAI users |

#### Ollama Setup (Local/On-Prem - Air-Gapped)

Ollama runs models locally -- no data leaves your infrastructure. For enterprises with strict data residency requirements.

```yaml
jobs:
  analyze:
    runs-on: self-hosted
    services:
      ollama:
        image: ollama/ollama
        ports:
          - 11434:11434
    steps:
      - uses: actions/checkout@v4
      - name: Pull Ollama model
        run: |
          curl -X POST http://localhost:11434/api/pull -d '{"name": "llama3.3"}'
      - uses: DNYoussef/codeguard-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          ollama_host: http://localhost:11434
          ollama_model: llama4
```

### Archive Evidence Bundles

```yaml
- uses: DNYoussef/codeguard-action@v1
  id: codeguard

- uses: actions/upload-artifact@v4
  with:
    name: evidence-bundle
    path: ${{ steps.codeguard.outputs.bundle_path }}
    retention-days: 2555  # 7 years for compliance
```

### Matrix Testing with Rubrics

```yaml
strategy:
  matrix:
    rubric: [soc2, hipaa, pci-dss]

steps:
  - uses: DNYoussef/codeguard-action@v1
    with:
      rubric: ${{ matrix.rubric }}
```

## Evidence Bundle Format

Bundles follow the [guardspine-spec](https://github.com/DNYoussef/guardspine-spec) v0.2.0/v0.2.1.
When PII-Shield is enabled, bundles include a `sanitization` attestation block (v0.2.1).
For backward compatibility, legacy `events` + `hash_chain` fields are still emitted:

```json
{
  "version": "0.2.0",
  "guardspine_spec_version": "0.2.0",
  "bundle_id": "gsb_abc123def456",
  "created_at": "2024-01-15T10:30:00Z",
  "context": {
    "repository": "acme/payments",
    "pr_number": 42,
    "commit_sha": "abc123..."
  },
  "events": [
    {"event_type": "pr_submitted", "hash": "..."},
    {"event_type": "analysis_completed", "hash": "..."},
    {"event_type": "risk_classified", "hash": "..."}
  ],
  "hash_chain": {
    "algorithm": "sha256",
    "final_hash": "...",
    "event_count": 3
  },
  "items": [
    {"item_id": "event-0000", "content_type": "guardspine/codeguard/pr_submitted", "content_hash": "sha256:..."}
  ],
  "immutability_proof": {
    "hash_chain": [{"sequence": 0, "chain_hash": "sha256:..."}],
    "root_hash": "sha256:..."
  },
  "summary": {
    "risk_tier": "L3",
    "requires_approval": true
  }
}
```

## Verification

Anyone can verify a bundle without trusting GuardSpine.

### Install Options

```bash
# Option 1: From Git (always works)
pip install git+https://github.com/DNYoussef/guardspine-verify

# Option 2: From PyPI (when available)
pip install guardspine-verify

# Option 3: Docker (zero dependencies)
docker run --rm -v $(pwd):/data ghcr.io/dnyoussef/guardspine-verify /data/bundle.json
```

### Verify a Bundle

![GuardSpine Verifier](docs/verifier-demo.png)

*Cryptographic verification with evidence summary -- no trust required*

```bash
guardspine-verify evidence-bundle.json

# Output:
# [OK] Hash chain verified (3 events)
# [OK] Final hash matches: abc123...
# [OK] Bundle integrity confirmed
```

## For AI Coding Agents

This section is for AI agents (Claude Code, Codex CLI, Gemini CLI, Aider, etc.) that are asked to set up code governance.

### Agent Installation Instructions

When a user asks you to "add code governance" or "set up GuardSpine", execute these steps:

```bash
# Step 1: Create workflow file
mkdir -p .github/workflows

# Step 2: Write the workflow
cat > .github/workflows/codeguard.yml << 'EOF'
name: CodeGuard
on:
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DNYoussef/codeguard-action@v1
        id: codeguard
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          risk_threshold: L3
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: evidence-bundle
          path: .guardspine/bundles/
EOF

# Step 3: Commit
git add .github/workflows/codeguard.yml
git commit -m "Add GuardSpine CodeGuard for PR governance"
```

### Agent Configuration Options

| User Request | Configuration |
|--------------|---------------|
| "strict governance" | `risk_threshold: L2, decision_policy: strict` |
| "only block critical" | `risk_threshold: L4` |
| "advisory mode" | `decision_policy: advisory` |
| "we're SOC 2" | `rubric: soc2` |
| "we handle health data" | `rubric: hipaa` |
| "we process payments" | `rubric: pci-dss` |
| "use local AI only" | Add `ollama_host: http://localhost:11434` |
| "use Claude for analysis" | Add `anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}` |
| "auto-merge clean PRs" | `auto_merge: true` |

### Agent Behavior Guidelines

1. **Always commit workflow files** -- do not just show the YAML, actually create the file
2. **Use appropriate rubric** -- if the codebase has `/auth`, `/payment`, or health-related code, suggest the matching rubric
3. **Explain outputs** -- tell the user they will see PR comments and can find bundles in workflow artifacts
4. **Do not overclaim** -- say "evidence mappings for audit support" not "makes you compliant"

### Detecting Existing Installation

Before installing, check:
```bash
# Check if already installed
if [ -f .github/workflows/codeguard.yml ]; then
  echo "CodeGuard already installed"
  cat .github/workflows/codeguard.yml
fi
```

---

## PII-Shield Integration

CodeGuard integrates [PII-Shield](https://github.com/aragossa/pii-shield) to prevent secrets and personally identifiable information from leaking into AI prompts, PR comments, and evidence bundles.

### Why PII-Shield Matters

Every AI code review sends diff content to language models. That diff might contain:

- **API keys** hardcoded during development (`sk_live_...`, `AKIA...`)
- **Database credentials** in migration files or config changes
- **PII** in test fixtures, seed data, or log format strings
- **Internal hostnames** and infrastructure details in config files

Without sanitization, these secrets get forwarded to whichever AI provider you have configured -- OpenRouter, Anthropic, OpenAI, or any other third party. Even with Ollama (local models), secrets persist in evidence bundles that may be stored for years and shared with auditors.

PII-Shield solves this by detecting high-entropy strings using **Shannon entropy analysis** combined with **bigram frequency detection** (real secrets have different character distribution than code identifiers). Detected secrets are replaced with deterministic HMAC tokens (`[HIDDEN:a1b2c3]`) so the same secret always maps to the same token within a bundle -- preserving referential integrity without exposing the underlying value.

### What PII-Shield Is

[PII-Shield](https://github.com/aragossa/pii-shield) is a Go-based Kubernetes sidecar created by [Ilya Ploskovitov](https://github.com/aragossa). It provides:

- **Entropy-based secret detection** -- no regex lists to maintain, catches novel secret formats
- **Deterministic HMAC redaction** -- same input always produces same token (keyed by org-wide salt)
- **Zero-config deployment** -- runs as a K8s sidecar or standalone HTTP service
- **Sub-millisecond latency** -- Go implementation, no external dependencies

### Where PII-Shield Runs in the Pipeline

```
PR Diff (raw)
  |
  +-- SHA-256 hash (raw diff preserved for integrity proof)
  |
  +-- PII-Shield sanitize -----> Sanitized diff
        |                            |
        |                     AI model review (Claude/GPT/Gemini/Ollama)
        |                            |
        +-- PR Comment (sanitized) --+
        |                            |
        +-- Evidence Bundle (sanitized, then hash-chained)
        |
        +-- SARIF output (sanitized)
```

The raw diff is **never** modified. PII-Shield operates on copies sent to AI models and external outputs. The evidence bundle hash chain covers the sanitized content, so verification remains valid.

### PII-Shield Configuration

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
    pii_shield_enabled: true
    pii_shield_endpoint: https://pii-shield.your-org.internal/sanitize
    pii_shield_salt_fingerprint: sha256:your-org-salt-fingerprint
    pii_shield_fail_closed: true
    pii_shield_sanitize_comments: true
    pii_shield_sanitize_bundle: true
    pii_shield_sanitize_sarif: true
  env:
    PII_SHIELD_API_KEY: ${{ secrets.PII_SHIELD_API_KEY }}
```

| Input | Default | Description |
|-------|---------|-------------|
| `pii_shield_enabled` | `false` | Enable PII-Shield sanitization |
| `pii_shield_mode` | `auto` | Detection mode: `auto`, `local`, or `remote` |
| `pii_shield_endpoint` | `""` | Remote PII-Shield API URL (empty = local mode) |
| `pii_shield_api_key` | `""` | API key for remote PII-Shield endpoint |
| `pii_shield_timeout` | `5` | HTTP timeout in seconds for remote calls |
| `pii_shield_salt_fingerprint` | `sha256:00000000` | Non-secret fingerprint identifying the HMAC salt |
| `pii_shield_fail_closed` | `true` | Fail the action if sanitization errors occur |
| `pii_shield_sanitize_comments` | `true` | Sanitize PR comments before posting |
| `pii_shield_sanitize_bundle` | `true` | Sanitize evidence bundles before writing |
| `pii_shield_sanitize_sarif` | `true` | Sanitize SARIF output before upload |

### Hash Field Preservation

GuardSpine's own SHA-256 hashes are high-entropy by design -- the exact thing PII-Shield is built to detect. Without special handling, PII-Shield would flag every `content_hash`, `chain_hash`, and `root_hash` in a bundle as a secret.

CodeGuard solves this by automatically extracting hash fields before sanitization and reinjecting them after. Fields matching these patterns are preserved:

- `*_hash`, `*_digest`, `*_checksum`, `*_hmac`, `*_signature`
- `root_hash`, `chain_hash`, `content_hash`, `previous_hash`, `diff_hash`
- `signature_value`, `signed_hash`

This means PII-Shield focuses on actual secrets in content fields while leaving the cryptographic structure intact.

### The PII_SALT Must Be Org-Wide

The HMAC salt used by PII-Shield **must be the same across all services** in your organization that produce or consume GuardSpine bundles. If codeguard-action, rlm-docsync, and adapter-webhook each use a different salt, the same secret will produce different `[HIDDEN:...]` tokens in each system -- breaking cross-bundle correlation and audit trail consistency.

Store the salt in a shared secret manager (Vault, AWS Secrets Manager, K8s Secret) and reference it from all services.

---

## Source Layout

```
codeguard-action/
  action.yml              GitHub Action definition (inputs, outputs, Docker)
  entrypoint.py           Main entrypoint, wires all components
  requirements.txt        Python dependencies
  Dockerfile              Docker image for GitHub Actions
  src/
    analyzer.py           Diff parser, sensitive zone detection, multi-model AI review
    risk_classifier.py    Risk tier classification (L0-L4), rubric evaluation
    decision_engine.py    Findings -> verdict (vendored from guardspine-product)
    bundle_generator.py   Evidence bundle creation (guardspine-spec v0.2.0)
    pr_commenter.py       Decision Card rendering and posting
    sarif_exporter.py     SARIF output for GitHub Security tab
    canonical_json.py     RFC 8785 canonical JSON serialization
    pii_shield.py         PII-Shield client (local + remote modes)
    decision_profiles/    YAML policy files (standard, strict, advisory)
    adapters/
      pii_wasm_client.py  WASM-based PII-Shield for local mode
  rubrics/
    builtin/              Shipped rubric YAML files (soc2, hipaa, pci-dss, etc.)
  tests/                  Test suite
  eval/                   Evaluation harness
  docs/                   Documentation and demo images
```

---

## FAQ

**Q: Does this replace code review?**
A: No. CodeGuard adds *evidence* to your existing review process. Humans still review; GuardSpine proves what they saw.

**Q: What if I disagree with the risk tier?**
A: The tier is based on file patterns, zone detection, and change size. You can adjust the threshold, create custom rubrics, or override risk patterns with a `risk_policy` YAML file.

**Q: Can AI block my PR?**
A: No. AI-generated findings are marked as opinions (non-provable). They can trigger `merge-with-conditions` to surface concerns for human review, but only provable deterministic findings can `block` a PR. This is enforced by the decision engine.

**Q: Is my code sent anywhere?**
A: Diffs are analyzed locally in the GitHub runner. AI features (optional) send diffs to your configured AI provider. Enable [PII-Shield](#pii-shield-integration) to automatically strip secrets and PII before anything leaves the runner.

**Q: Do I need PII-Shield?**
A: If you use AI review (OpenRouter, Anthropic, OpenAI), PII-Shield prevents secrets in diffs from reaching third-party APIs. If you only use Ollama (local), PII-Shield still sanitizes evidence bundles that may be stored long-term or shared with auditors. It is optional but strongly recommended for production.

**Q: How long should I keep bundles?**
A: SOC 2 typically requires 1 year, HIPAA 6 years, PCI-DSS varies. Consult your compliance team.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License -- see [LICENSE](LICENSE) for details.

---

**GuardSpine** -- Evidence infrastructure for AI-mediated work.

[Website](https://guardspine.ai) | [Docs](https://docs.guardspine.ai)
