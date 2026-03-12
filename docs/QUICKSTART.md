GuardSpine CodeGuard -- 5-Minute Quickstart
============================================

Get AI-powered code governance with tamper-proof evidence on every pull request.

What you'll have in 5 minutes:
- Every PR gets a risk assessment (L0-L4) with AI analysis
- A cryptographic evidence bundle proving what was reviewed and when
- A Decision Card comment on each PR showing findings and risk drivers
- Audit-ready artifacts for SOC 2, HIPAA, or PCI-DSS


STEP 1: Add an API key (1 minute)
----------------------------------

Go to your repo: Settings > Secrets and variables > Actions > New repository secret

You need ONE of these (pick whichever you already have):

  OPENROUTER_API_KEY    Recommended. One key, 100+ models. Get one at openrouter.ai
  ANTHROPIC_API_KEY     Direct Claude access. console.anthropic.com
  OPENAI_API_KEY        Direct GPT access. platform.openai.com

No API key? CodeGuard still works in rules-only mode (risk tiers + evidence
bundles, no AI review). You can add a key later.


STEP 2: Add the workflow file (2 minutes)
-----------------------------------------

Create this file in your repo:

  .github/workflows/codeguard.yml

Paste this content:

```yaml
name: CodeGuard
on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: DNYoussef/codeguard-action@v1
        id: guard
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: evidence-bundle-${{ github.event.pull_request.number }}
          path: .guardspine/bundles/
```

That's the minimal config. Commit it to your default branch.


STEP 3: Open a pull request (1 minute)
---------------------------------------

Make any change on a branch and open a PR. CodeGuard runs automatically.

First run takes ~2 minutes while GitHub builds the Docker image. Subsequent
runs reuse the cached image and finish faster.

Within 1-2 minutes you'll see:

  1. A "Decision Card" comment on the PR:
     - Risk tier (L0 Trivial through L4 Critical)
     - Top risk drivers (which files/zones triggered the tier)
     - AI findings (what the models flagged)
     - Approval requirement (auto-approve or human review needed)

  2. An evidence bundle in the workflow artifacts:
     - Click "Actions" tab > select the run > download "evidence-bundle-NN"
     - JSON file with hash-chained event log, diff snapshot, and risk data
     - Cryptographically tamper-evident: any modification breaks the hash chain


STEP 4: Verify a bundle (1 minute, optional)
---------------------------------------------

Download the evidence bundle JSON from the workflow artifacts, then:

  pip install git+https://github.com/DNYoussef/guardspine-verify
  guardspine-verify evidence-bundle.json

Output shows: hash chain integrity, event sequence, and whether any
data was modified after generation.


YOU'RE DONE
-----------

Every PR in this repo now gets:
- Automated risk classification
- AI-powered code review (scales with risk: more models for higher-risk changes)
- A tamper-proof evidence bundle for audit

Next steps (when you're ready):

  Add a compliance rubric       rubric: soc2       (or hipaa, pci-dss)
  Block high-risk merges        fail_on_high_risk: true
  Enable PII redaction          pii_shield_enabled: true
  Upload to Security tab        upload_sarif: true
  Auto-merge clean PRs          auto_merge: true
  Use specific models           model_1: anthropic/claude-sonnet-4.5
                                model_2: openai/gpt-4.1
                                model_3: google/gemini-2.5-flash


CONFIGURATION CHEAT SHEET
--------------------------

Minimal (rules + single AI model):

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
```

Standard (compliance rubric + block high risk):

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
    rubric: soc2
    risk_threshold: L3
    fail_on_high_risk: true
```

Enterprise (multi-model + PII protection + SARIF):

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
    rubric: hipaa
    risk_threshold: L2
    fail_on_high_risk: true
    upload_sarif: true
    pii_shield_enabled: true
    model_1: anthropic/claude-sonnet-4.5
    model_2: openai/gpt-4.1
    model_3: google/gemini-2.5-flash
```

Air-gapped (Ollama, no external API calls):

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    ollama_host: http://your-ollama-server:11434
    ollama_model: llama3.3
    ai_review: true
```


RISK TIERS EXPLAINED
--------------------

  L0  Trivial     Docs, comments, formatting. 0 AI models. Auto-approve.
  L1  Low         Tests, non-critical code. 1 AI model. Auto-approve.
  L2  Medium      Feature code, minor logic. 2 AI models. Auto-approve.
  L3  High        Auth, config, sensitive zones. 3 AI models. Requires approval.
  L4  Critical    Payments, PII, security, crypto. 3 AI models. Requires HUMAN approval.

The risk_threshold input controls where the gate kicks in. Default: L3.


WHAT'S IN AN EVIDENCE BUNDLE
-----------------------------

Each bundle is a JSON file containing:

  events[]        Hash-chained event sequence (PR opened, analysis complete,
                  risk classified, approval recorded). Each event includes
                  the hash of the previous event -- tampering with any event
                  breaks the chain.

  content_hash    SHA-256 of the PR diff at analysis time. Proves the exact
                  code that was reviewed.

  risk_tier       The assessed risk level and the drivers that produced it.

  findings[]      Policy violations or concerns found by AI review.

  metadata        Repo, PR number, commit SHA, timestamp, models used.

Bundles are independently verifiable. You don't need GuardSpine running
to check one -- just the guardspine-verify CLI.


TROUBLESHOOTING
---------------

"No AI review happened"
  At least one API key must be set as a repo secret. Check that the
  secret name matches exactly (OPENROUTER_API_KEY, not OpenRouter_Key).

"Action not found"
  Make sure you're using: DNYoussef/codeguard-action@v1 (case-sensitive).

"Evidence bundle missing"
  The upload-artifact step needs path: .guardspine/bundles/ (with trailing /).
  If you changed bundle_dir, update the upload path to match.

"Check failed unexpectedly"
  Set fail_on_high_risk: false (default) to run in advisory mode. The action
  posts findings but does not block merges.

"PII-Shield errors"
  Set pii_shield_fail_closed: false for advisory mode, or check your
  PII_SHIELD_ENDPOINT connectivity.


SUPPORT
-------

Issues: https://github.com/DNYoussef/codeguard-action/issues
Email: team@guardspine.ai
