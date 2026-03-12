# CodeGuard Validation Test Harness

Deterministic pytest suite that validates CodeGuard against synthetic minimal-reproduction PR diffs derived from real incident patterns.

**Primary success metric: false negatives on L2-L4.**

## Quick Start

```bash
cd codeguard-tests
pip install pytest
pytest -v
```

This runs in **replay mode** (default), loading pre-built fixture responses from `fixtures/outputs/`. No API keys or live CodeGuard instance needed.

## Test Cases (12 total)

| ID | Level | Pattern | Real Incident |
|----|-------|---------|---------------|
| TC-001 | L4 | Build system injection backdoor | XZ Utils (CVE-2024-3094) |
| TC-002 | L4 | CI/CD credential exfiltration | Codecov (2021) |
| TC-003 | L4 | Missing bounds check in TLS | Heartbleed (CVE-2014-0160) |
| TC-004 | L3 | Dependency hijack | event-stream (CVE-2018-16396) |
| TC-005 | L3 | Unsanitized input to logger | Log4Shell (CVE-2021-44228) |
| TC-006 | L3 | ORM bypass / SQL injection | OWASP A03 |
| TC-007 | L2 | Hardcoded credentials | OWASP A07 |
| TC-008 | L2 | Prototype pollution | lodash (CVE-2019-10744) |
| TC-009 | L1 | Trivial dependency | leftpad (2016) |
| TC-010 | L1 | Semantic-preserving refactor | N/A (control) |
| TC-011 | L0 | Pure whitespace/formatting | N/A (control) |
| TC-012 | L0 | Comment-only changes | N/A (control) |

## Test Functions

- **test_detection** -- Did CodeGuard catch the issue? (L0 controls should NOT detect)
- **test_classification** -- Risk level: strict match for L4, +/-1 tolerance for others
- **test_council_consensus** -- L2+ only: naive hit rate, round-robin delta, consensus correctness, actionability
- **test_controls_do_not_overflag** -- L0 must not detect, L1 must not classify as L2+

## Modes

### Replay (default)

Loads deterministic JSON fixtures from `fixtures/outputs/`. Safe for CI.

### Live

Set `CODEGUARD_LIVE=1` to run against the real CodeGuard action. Live mode does NOT gate CI pass/fail -- it generates a separate report and optionally updates fixtures.

```bash
CODEGUARD_LIVE=1 pytest -v
```

> **Note:** Live mode is not yet wired. See `lib/codeguard_runner.py` for integration points.

## Reports

After a test run, reports are generated in `reports/`:

- **summary.md** -- Human-readable: per-case table, confusion matrix, FN/FP rates, council metrics
- **summary.json** -- Machine-readable version of everything above

## Validation Metrics

| Metric | Definition |
|--------|------------|
| Detection | `detected==true` OR `risk_level>=1` OR expected signal found |
| Strict classification | `output.risk_level == expected` |
| Tolerant classification | `abs(output - expected) <= 1` (L4 strict only) |
| Naive hit rate | % models with >=1 expected signal in naive phase |
| Round-robin delta | Per model: +N/-N/0 coverage change after cross-check |
| Consensus correctness | Consensus risk_level passes classification rules |
| Actionability | % findings with both remediation AND file path |

## Repo Structure

```
codeguard-tests/
|-- conftest.py                     # Shared fixtures, runner, report hook
|-- test_codeguard.py               # 4 test functions
|-- test_cases/
|   |-- known_incidents.py          # 12 test cases with diffs
|   +-- ground_truth.py             # Enums, TestCase dataclass
|-- lib/
|   |-- codeguard_runner.py         # run(case, mode) -> ParsedResult
|   |-- diff_builder.py             # Temp git repo construction
|   |-- council_analyzer.py         # Council scoring rubric
|   +-- report_generator.py         # summary.md + summary.json
|-- mocks/
|   +-- mock_github_context.py      # Simulated GitHub PR context
|-- fixtures/
|   +-- outputs/                    # One JSON per test case (replay mode)
|       |-- TC-001.json ... TC-012.json
+-- reports/
    +-- .gitkeep
```

## Future Extensions (Not Implemented)

- Benign auth/config changes (should stay L2, not escalate)
- Safe crypto changes (hash algorithm swap with correct usage)
- Legitimate obfuscation (minified JS) vs malicious (packed payload)
- Secrets in test fixtures vs production config (context matters)
- Lockfile-only dependency bumps (should be L0 or L1)
