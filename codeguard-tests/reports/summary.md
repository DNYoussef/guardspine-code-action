# CodeGuard Validation Report

Generated: 2026-02-18T13:06:50.220267+00:00
Total cases: 12

## Headline Metrics

- **False Negative Rate (L2-L4):** 0.0%
- **False Positive Rate (L0):** 0.0%

## Per-Case Results

| Case | Expected | Actual | Detected | Strict | Tolerant | Pass |
|------|----------|--------|----------|--------|----------|------|
| TC-001 | L4 | L4 | Y | Y | Y | PASS |
| TC-002 | L4 | L4 | Y | Y | Y | PASS |
| TC-003 | L4 | L4 | Y | Y | Y | PASS |
| TC-004 | L3 | L3 | Y | Y | Y | PASS |
| TC-005 | L3 | L3 | Y | Y | Y | PASS |
| TC-006 | L3 | L3 | Y | Y | Y | PASS |
| TC-007 | L2 | L2 | Y | Y | Y | PASS |
| TC-008 | L2 | L2 | Y | Y | Y | PASS |
| TC-009 | L1 | L1 | Y | Y | Y | PASS |
| TC-010 | L1 | L1 | Y | Y | Y | PASS |
| TC-011 | L0 | L0 | N | Y | Y | PASS |
| TC-012 | L0 | L0 | N | Y | Y | PASS |

## Confusion Matrix (Expected x Actual)

|  | L0 | L1 | L2 | L3 | L4 |
|--|----|----|----|----|-----|
| **L0** | 2 | 0 | 0 | 0 | 0 |
| **L1** | 0 | 2 | 0 | 0 | 0 |
| **L2** | 0 | 0 | 2 | 0 | 0 |
| **L3** | 0 | 0 | 0 | 3 | 0 |
| **L4** | 0 | 0 | 0 | 0 | 3 |

## Council Effectiveness (L2+ only)

- **Avg Naive Hit Rate:** 100.0%
- **Consensus Correct Rate:** 100.0%
- **Avg Actionability:** 100.0%

### Round-Robin Delta by Case

- **TC-001:** claude-sonnet-4-5: 0, gpt-4o: 0, gemini-2.0-flash: 0
- **TC-002:** claude-sonnet-4-5: 0, gpt-4o: 0, gemini-2.0-flash: +1
- **TC-003:** claude-sonnet-4-5: 0, gpt-4o: 0, gemini-2.0-flash: +1
- **TC-004:** claude-sonnet-4-5: 0, gpt-4o: 0
- **TC-005:** claude-sonnet-4-5: 0, gpt-4o: 0, gemini-2.0-flash: +1
- **TC-006:** claude-sonnet-4-5: 0, gpt-4o: 0, gemini-2.0-flash: 0
- **TC-007:** claude-sonnet-4-5: 0, gpt-4o: 0
- **TC-008:** claude-sonnet-4-5: 0, gpt-4o: 0

## Per-Model Breakdown

| Model | Cases | +Delta | -Delta | Neutral |
|-------|-------|--------|--------|---------|
| claude-sonnet-4-5 | 8 | 0 | 0 | 8 |
| gpt-4o | 8 | 0 | 0 | 8 |
| gemini-2.0-flash | 5 | 3 | 0 | 2 |
