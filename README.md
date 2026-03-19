# GuardSpine CodeGuard

**AI-aware code governance with cryptographically verifiable evidence bundles**

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

**3. Open a PR.** You'll see a Decision Card comment with risk tier + findings, and the evidence bundle in workflow artifacts.

**Verify a bundle locally** (optional):
```bash
pip install guardspine-verify && guardspine-verify .guardspine/bundles/*.json
```

> **Troubleshooting**: Missing artifact? Ensure `bundle_dir` matches upload path. Hard fail on L4? Set `fail_on_high_risk: false` (default). No AI review? Provide at least one API key and set `ai_review: true` (default). PII-Shield failing? Check endpoint connectivity or set `pii_shield_fail_closed: false` for advisory mode.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GUARDSPINE CODEGUARD FLOW                           │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────┐
  │ PR Open  │
  │ /Update  │
  └────┬─────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                           1. DIFF ANALYSIS                                │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  • Parse unified diff (unidiff)                                     │ │
│  │  • Extract file changes, hunks, line-level modifications            │ │
│  │  • Detect 13 sensitive zones:                                       │ │
│  │    [auth] [payment] [crypto] [database] [security] [pii] [config]   │ │
│  │    [infra]                                                          │ │
│  │  • Generate SHA-256 diff hash for integrity                         │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    2. TIER-BASED MULTI-MODEL AI REVIEW                   │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Models scale with risk tier (not fallback - actual multi-review):  │ │
│  │                                                                     │ │
│  │   L0 (Trivial)  → 0 models  (rules-based only, no AI)              │ │
│  │   L1 (Low)      → 1 model   (single model review)                  │ │
│  │   L2 (Medium)   → 2 models  + rubric scoring                       │ │
│  │   L3 (High)     → 3 models  + rubric scoring                       │ │
│  │   L4 (Critical) → 3 models  + rubric scoring + human approval      │ │
│  │                                                                     │ │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                             │ │
│  │  │ Model 1 │  │ Model 2 │  │ Model 3 │  ← Run in PARALLEL          │ │
│  │  │ Claude  │  │  GPT    │  │ Gemini  │                             │ │
│  │  └────┬────┘  └────┬────┘  └────┬────┘                             │ │
│  │       │            │            │                                   │ │
│  │       └────────────┼────────────┘                                   │ │
│  │                    ▼                                                │ │
│  │            ┌──────────────┐                                         │ │
│  │            │  CONSENSUS   │  Majority vote + rubric aggregation    │ │
│  │            │  CALCULATOR  │  Agreement score + dissent tracking    │ │
│  │            └──────────────┘                                         │ │
│  │                                                                     │ │
│  │  Flexible model selection:                                          │ │
│  │   • All 3 from Ollama (air-gapped)                                 │ │
│  │   • All 3 from OpenRouter (100+ models)                            │ │
│  │   • Mix of direct APIs (Claude + GPT + Gemini)                     │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        3. RISK CLASSIFICATION                             │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Three scoring dimensions → Final risk tier:                        │ │
│  │                                                                     │ │
│  │   File Patterns ──────┐                                             │ │
│  │   (auth/payment/pii)  │                                             │ │
│  │                       ├──→ max(scores) ──→ ┌────────────────────┐   │ │
│  │   Sensitive Zones ────┤                    │   L0 │ Trivial     │   │ │
│  │   (13 zone types)     │                    │   L1 │ Low         │   │ │
│  │                       │                    │   L2 │ Medium      │   │ │
│  │   Change Size ────────┘                    │   L3 │ High    ⚠️  │   │ │
│  │   (lines added/removed)                    │   L4 │ Critical ⛔ │   │ │
│  │                                            └────────────────────┘   │ │
│  │                                                                     │ │
│  │  Rubric boost: SOC2/HIPAA/PCI-DSS rules can escalate tier          │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
       │
       ├──────────────────────────────────────┐
       ▼                                      ▼
┌────────────────────┐              ┌────────────────────┐
│ L0-L2: Auto-pass   │              │ L3-L4: Block merge │
│ ✓ PR check passes  │              │ ⚠ Requires review  │
│ ✓ Comment posted   │              │ ⛔ Human approval  │
└────────────────────┘              └────────────────────┘
       │                                      │
       └──────────────────┬───────────────────┘
                          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                      4. EVIDENCE BUNDLE GENERATION                        │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Hash-chained event sequence (tamper-evident):                      │ │
│  │                                                                     │ │
│  │   Event 1           Event 2            Event 3          Event 4     │ │
│  │  ┌─────────┐       ┌─────────┐        ┌─────────┐      ┌─────────┐  │ │
│  │  │   PR    │──H1──▶│Analysis │──H2───▶│  Risk   │─H3──▶│Approval │  │ │
│  │  │Submitted│       │Complete │        │Classify │      │(if L3+) │  │ │
│  │  └─────────┘       └─────────┘        └─────────┘      └─────────┘  │ │
│  │       │                                                     │       │ │
│  │       └───────────────── Final Hash ────────────────────────┘       │ │
│  │                                                                     │ │
│  │  Bundle includes: diff snapshot, risk drivers, findings, rationale │ │
│  │  Supports: Ed25519, RSA, ECDSA, or HMAC-SHA256 signatures          │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                           5. OUTPUT ARTIFACTS                             │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────┐  │
│  │  Diff Postcard │  │ Evidence Bundle│  │     SARIF Export           │  │
│  │  (PR Comment)  │  │  (JSON file)   │  │  (GitHub Security Tab)     │  │
│  │                │  │                │  │                            │  │
│  │ • Risk tier    │  │ • Hash chain   │  │ • Findings as alerts       │  │
│  │ • Top drivers  │  │ • Event log    │  │ • File locations           │  │
│  │ • Findings     │  │ • Signatures   │  │ • Severity mapping         │  │
│  │ • AI summary   │  │ • Snapshot     │  │                            │  │
│  └────────────────┘  └────────────────┘  └────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

### Tier-Based Multi-Model Review

CodeGuard uses **escalating AI review** - more models review higher-risk changes:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     TIER-BASED MODEL ESCALATION                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   L0 (Trivial)   →  0 models   Rules-based only (docs, formatting)      │
│   L1 (Low)       →  1 model    Single model review                      │
│   L2 (Medium)    →  2 models   Dual review + rubric scoring             │
│   L3 (High)      →  3 models   Triple review + rubric + approval req    │
│   L4 (Critical)  →  3 models   Triple review + rubric + HUMAN approval  │
│                                                                          │
│   ┌──────────────────────────────────────────────────────────────────┐  │
│   │  CONSENSUS OUTPUT:                                               │  │
│   │   • consensus_risk: "approve" | "request_changes" | "comment"    │  │
│   │   • agreement_score: 0.0 - 1.0 (model agreement %)               │  │
│   │   • combined_concerns: deduplicated from all models              │  │
│   │   • rubric_summary: averaged scores per dimension                │  │
│   │   • dissenting_opinions: models that disagreed                   │  │
│   └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Flexible Model Configuration

Configure **any combination** of models - same provider or mixed:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     EXAMPLE CONFIGURATIONS                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Option 1: All OpenRouter (recommended - single API)                     │
│    model_1: anthropic/claude-sonnet-4.5                                  │
│    model_2: openai/gpt-5.2                                               │
│    model_3: google/gemini-3-flash                                        │
│                                                                          │
│  Option 2: All Ollama (air-gapped)                                       │
│    model_1: llama4                                                       │
│    model_2: mistral-large                                                │
│    model_3: codellama-70b                                                │
│                                                                          │
│  Option 3: Mixed direct APIs                                             │
│    model_1: claude-haiku-4-5-20251001  (anthropic_api_key)               │
│    model_2: gpt-4.1-mini              (openai_api_key)                   │
│    model_3: llama4              (ollama_host)                            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

| Provider | Data Residency | Default Models | Best For |
|----------|----------------|----------------|----------|
| **Ollama** | Your infrastructure | llama4, mistral-large, codellama-70b | Air-gapped/regulated |
| **OpenRouter** | OpenRouter servers | Claude 4.5, GPT 5.2, Gemini 3 | Flexibility, diversity |
| **Anthropic** | Anthropic servers | Claude Haiku 4.5 | Direct Claude access |
| **OpenAI** | OpenAI servers | GPT 4.1 Mini | Existing OpenAI users |

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

### Diff Postcard (PR Comment)

Every PR gets a summary comment showing:
- Risk tier with visual indicator
- Top risk drivers (why this tier?)
- Findings from policy evaluation
- Approval requirements

### Evidence Bundles

Cryptographically verifiable JSON bundles containing:
- Hash-chained event sequence
- Diff snapshot at analysis time
- Risk assessment details
- Approval records (when applicable)

Verify any bundle independently - see [Verification](#verification) section below.

### Evidence Mappings for Audit Support

Pre-built rule sets that map findings to audit frameworks:
- **SOC 2** - CC6, CC7, CC8 control evidence
- **HIPAA** - 164.312 safeguard documentation
- **PCI-DSS** - Requirement 3, 6, 8 evidence exports

> **Note**: These are *evidence mappings* that help document your existing controls - they don't make you compliant by themselves. Always work with your auditors.

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    rubric: hipaa  # or: soc2, pci-dss, default
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

## Configuration

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `risk_threshold` | Tier at which to require approval (L0-L4) | `L3` |
| `rubric` | Policy rubric (default, security, soc2, hipaa, pci-dss, or custom YAML path) | `default` |
| `github_token` | GitHub token for PR operations | Required |
| `post_comment` | Post Diff Postcard comment | `true` |
| `generate_bundle` | Create evidence bundle artifact | `true` |
| `upload_sarif` | Upload to GitHub Security tab | `false` |
| `fail_on_high_risk` | Block merge if over threshold (exit 1) | `false` |
| `rubrics_dir` | Directory containing rubric YAML files | `.guardspine/rubrics` |
| `risk_policy` | Path to YAML that overrides risk patterns/thresholds | - |
| `bundle_dir` | Directory to write evidence bundles | `.guardspine/bundles` |
| `confidence_calibrator` | Optional JSON artifact for calibrated `P(consensus verdict is correct)` | - |
| **Model Configuration** | | |
| `model_1` | First model (L1+). Format: `provider/model` or just `model` | Auto-detect |
| `model_2` | Second model (L2+). Format: `provider/model` or just `model` | Auto-detect |
| `model_3` | Third model (L3+). Format: `provider/model` or just `model` | Auto-detect |
| **API Keys** | | |
| `openai_api_key` | OpenAI key for GPT models (optional) | - |
| `anthropic_api_key` | Anthropic key for Claude models (optional) | - |
| `openrouter_api_key` | OpenRouter key (access 100+ models) (optional) | - |
| `ollama_host` | Ollama server URL for local AI (optional) | - |

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
| `calibrated_confidence` | Optional calibrated probability that the consensus verdict is correct |
| `confidence_source` | Source label for calibrated confidence metadata |

### Confidence Calibration

The action can attach a calibrated confidence score to the multi-model consensus without changing the review models or
the inference path. This is a black-box calibrator trained on eval outcomes, not a self-reported model confidence.

One-shot helper for the default corpora (`hand-crafted` + `real-cve`):

```bash
python eval/train_confidence_from_corpora.py
```

That writes merged rows under `eval/results/` and the calibrator artifact to
`.guardspine/calibration/codeguard-confidence-v1.json`.

1. Export labeled rows from eval:

```bash
python eval/run_eval.py --dataset hand-crafted --emit-calibration-jsonl eval/results/calibration.jsonl
```

2. Train a lean JSON artifact:

```bash
python eval/train_confidence_calibrator.py \
  --input eval/results/calibration.jsonl \
  --output .guardspine/calibration/codeguard-confidence-v1.json
```

3. Apply it from the monorepo workflow:

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    confidence_calibrator: .guardspine/calibration/codeguard-confidence-v1.json
```

When present, the artifact adds `calibrated_confidence` to action outputs and `confidence_calibration` metadata to the
evidence bundle snapshot.

## Advanced Usage

### Custom Risk Threshold per Branch

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    risk_threshold: ${{ github.base_ref == 'main' && 'L2' || 'L3' }}
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

**Popular OpenRouter models (Jan 2026):**
| Model | ID | Best For |
|-------|-----|----------|
| Claude 4.5 Sonnet | `anthropic/claude-sonnet-4.5` | Fast + quality (default) |
| Claude 4.5 Opus | `anthropic/claude-4.5-opus` | Best reasoning |
| GPT 5.2 | `openai/gpt-5.2` | Good balance |
| Gemini 3 Flash | `google/gemini-3-flash` | Fast, multimodal |
| Llama 4 70B | `meta-llama/llama-4-70b-instruct` | Open source |

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
    model_3: llama4              # Uses Ollama
```

#### Option 4: Single Provider (legacy/simple)

Just provide one API key - CodeGuard will use default models:

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

#### Ollama Setup (Local/On-Prem - Air-Gapped)

Ollama runs models locally - no data leaves your infrastructure. Perfect for enterprises with strict data residency requirements.

**Step 1: Install Ollama on your runner**

For self-hosted runners:
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.3
```

**Step 2: Start Ollama service**

Add a service step before CodeGuard:
```yaml
jobs:
  analyze:
    runs-on: self-hosted  # or ubuntu-latest with Ollama installed
    services:
      ollama:
        image: ollama/ollama
        ports:
          - 11434:11434
    steps:
      - uses: actions/checkout@v4

      # Pull model (one-time setup)
      - name: Pull Ollama model
        run: |
          curl -X POST http://localhost:11434/api/pull -d '{"name": "llama3.3"}'

      - uses: DNYoussef/codeguard-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          ollama_host: http://localhost:11434
          ollama_model: llama4
```

**Popular Ollama models (Jan 2026):**
| Model | ID | Size | Best For |
|-------|-----|------|----------|
| Llama 4 70B | `llama4` | 40GB | Best quality |
| Llama 4 8B | `llama4:8b` | 5GB | Fast, balanced |
| CodeLlama 70B | `codellama-70b` | 40GB | Code-focused |
| Mistral Large | `mistral-large` | 12GB | Good reasoning |
| Mixtral 8x22B | `mixtral-8x22b` | 80GB | MoE architecture |
| Phi-4 | `phi4` | 4GB | Microsoft's compact |
| Qwen 3 | `qwen3` | 8GB | Multilingual |

**Remote Ollama server:**
```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    ollama_host: http://your-ollama-server.internal:11434
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

*Cryptographic verification with evidence summary - no trust required*

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
| "strict governance" | `risk_threshold: L2` |
| "only block critical" | `risk_threshold: L4` |
| "we're SOC 2" | `rubric: soc2` |
| "we handle health data" | `rubric: hipaa` |
| "we process payments" | `rubric: pci-dss` |
| "use local AI only" | Add `ollama_host: http://localhost:11434` |
| "use Claude for analysis" | Add `anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}` |

### Agent Behavior Guidelines

1. **Always commit workflow files** - Don't just show the YAML, actually create the file
2. **Use appropriate rubric** - If the codebase has `/auth`, `/payment`, or health-related code, suggest the matching rubric
3. **Explain outputs** - Tell the user they'll see PR comments and can find bundles in workflow artifacts
4. **Don't overclaim** - Say "evidence mappings for audit support" not "makes you compliant"

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

Without sanitization, these secrets get forwarded to whichever AI provider you've configured -- OpenRouter, Anthropic, OpenAI, or any other third party. Even with Ollama (local models), secrets persist in evidence bundles that may be stored for years and shared with auditors.

PII-Shield solves this by detecting high-entropy strings using **Shannon entropy analysis** combined with **bigram frequency detection** (real secrets have different character distribution than code identifiers). Detected secrets are replaced with deterministic HMAC tokens (`[HIDDEN:a1b2c3]`) so the same secret always maps to the same token within a bundle -- preserving referential integrity without exposing the underlying value.

### What PII-Shield Is

[PII-Shield](https://github.com/aragossa/pii-shield) is a Go-based Kubernetes sidecar created by [Ilya Ploskovitov](https://github.com/aragossa). It provides:

- **Entropy-based secret detection** -- no regex lists to maintain, catches novel secret formats
- **Deterministic HMAC redaction** -- same input always produces same token (keyed by org-wide salt)
- **Zero-config deployment** -- runs as a K8s sidecar or standalone HTTP service
- **Sub-millisecond latency** -- Go implementation, no external dependencies

### Installing PII-Shield

**Option 1: Kubernetes sidecar (recommended for production)**

```yaml
# In your deployment manifest
containers:
  - name: pii-shield
    image: ghcr.io/aragossa/pii-shield:latest
    ports:
      - containerPort: 8080
    env:
      - name: PII_SALT
        valueFrom:
          secretKeyRef:
            name: pii-shield-config
            key: salt
```

**Option 2: Docker standalone**

```bash
docker run -d -p 8080:8080 \
  -e PII_SALT=your-org-wide-salt \
  ghcr.io/aragossa/pii-shield:latest
```

**Option 3: Local mode (no server needed)**

CodeGuard includes a built-in local entropy detector that runs entirely within the GitHub Action runner. No PII-Shield server required -- just enable it:

```yaml
pii_shield_enabled: true
# No endpoint = local mode (entropy detection only, no HMAC)
```

Local mode uses Shannon entropy analysis to flag high-entropy strings but cannot produce deterministic HMAC tokens (since there's no shared salt). Use remote mode for cross-bundle token consistency.

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

The raw diff is **never** modified. PII-Shield operates on copies sent to AI models and external outputs. The evidence bundle's hash chain covers the sanitized content, so verification remains valid.

### Configuration

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
    # PII-Shield configuration
    pii_shield_enabled: true
    pii_shield_endpoint: https://pii-shield.your-org.internal/sanitize
    pii_shield_salt_fingerprint: sha256:your-org-salt-fingerprint
    pii_shield_fail_closed: true           # fail the action on sanitization error
    pii_shield_sanitize_comments: true     # sanitize PR comment body
    pii_shield_sanitize_bundle: true       # sanitize evidence bundle content
    pii_shield_sanitize_sarif: true        # sanitize SARIF findings
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

### Custom Regex Whitelist (PII_SAFE_REGEX_LIST)

For patterns that PII-Shield's entropy detector shouldn't flag (e.g., base64-encoded config values, JWT tokens in test fixtures), you can pass a custom regex whitelist:

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    pii_shield_enabled: true
    pii_safe_regex_list: 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+,GUARDSPINE_[A-Z_]+'
```

| Input | Default | Description |
|-------|---------|-------------|
| `pii_safe_regex_list` | `""` | Comma-separated regex patterns to whitelist from PII detection |

Each pattern is compiled as a Python regex. Strings matching any pattern are passed through without redaction. Use this sparingly -- the default hash field preservation handles the common case.

### The PII_SALT Must Be Org-Wide

The HMAC salt used by PII-Shield **must be the same across all services** in your organization that produce or consume GuardSpine bundles. If codeguard-action, rlm-docsync, and adapter-webhook each use a different salt, the same secret will produce different `[HIDDEN:...]` tokens in each system -- breaking cross-bundle correlation and audit trail consistency.

Store the salt in a shared secret manager (Vault, AWS Secrets Manager, K8s Secret) and reference it from all services.

### Across the GuardSpine Ecosystem

PII-Shield is integrated across the entire GuardSpine stack:

| Component | What Gets Sanitized | Status |
|-----------|---------------------|--------|
| **codeguard-action** | PR diffs, comments, bundles, SARIF | Active |
| **guardspine-verify** | Validates sanitization attestations | Active |
| **rlm-docsync** | Documentation claims and evidence packs | Active |
| **guardspine-local-council** | Prompts sent to local Ollama models | Active |
| **guardspine-adapter-webhook** | Webhook payloads before bundle creation | Active |
| **guardspine-spec** | Defines the sanitization attestation schema (v0.2.1) | Active |

All components produce a standardized `sanitization` attestation block (GuardSpine spec v0.2.1) documenting the engine, method, redaction count, and token format. The verifier checks this attestation for consistency.

---

## Recent Hardening

Security audit fixes applied in Feb 2026:

- **Canonicalization alignment**: `canonical_json.py` now matches the TS kernel exactly (no NFC normalization, no trailing newlines). Cross-language parity tests pass.
- **SSRF hardening**: all outbound HTTP calls (PII-Shield, AI providers, webhook endpoints) validate URL schemes and reject private/internal IP ranges.
- **Deterministic bundle IDs**: bundle IDs are now derived from content hash instead of random UUIDs, making bundles reproducible.
- **Incremental root hash**: root hash computation uses streaming SHA-256 instead of string concatenation.
- **Decision engine vendored**: the risk classification engine is vendored inline (no external dependency at runtime).

---

## FAQ

**Q: Does this replace code review?**
A: No. CodeGuard adds *evidence* to your existing review process. Humans still review; GuardSpine proves what they saw.

**Q: What if I disagree with the risk tier?**
A: The tier is based on file patterns and content analysis. You can adjust the threshold or create custom rubrics.

**Q: Is my code sent anywhere?**
A: Diffs are analyzed locally in the GitHub runner. AI features (optional) send diffs to your configured AI provider. Enable [PII-Shield](#pii-shield-integration) to automatically strip secrets and PII before anything leaves the runner.

**Q: Do I need PII-Shield?**
A: If you use AI review (OpenRouter, Anthropic, OpenAI), PII-Shield prevents secrets in diffs from reaching third-party APIs. If you only use Ollama (local), PII-Shield still sanitizes evidence bundles that may be stored long-term or shared with auditors. It's optional but strongly recommended for production.

**Q: How long should I keep bundles?**
A: SOC 2 typically requires 1 year, HIPAA 6 years, PCI-DSS varies. Consult your compliance team.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**GuardSpine** - Evidence infrastructure for AI-mediated work.

[Website](https://guardspine.io) | [Docs](https://docs.guardspine.io) | [Support](mailto:support@guardspine.io)
