# Gates: adapter failure contract

OWNS: src/pii_shield.py, tests/test_pii_shield_failure_contract.py, tests/test_pii_shield_fatal_result.py, docs/operations/adapter-failure-20260908/**, .github/workflows/candidate-fatal-result.yml, docs/operations/fatal-result-20260908/verify_linux.py, docs/operations/fatal-result-20260908/GATES.md

Scope: privacy-safe engine/JSON failure reporting with truthful existing result fields.
Entry-point reporting and remaining Action/native acceptance are separate open leaves.

This leaf supersedes the prior fatal-result GATES description of verify_linux.py:
the candidate verifier now checks ten byte controls and 87 cases, plus the
guard-removal mutation. The prior 24/30 unit counts and six-hash/54-case execution
belong to commit 5e71aa1 and remain recorded there; they are not new-run evidence.
Complete candidate identity is the reviewed Git commit/tree plus independently
checked GitHub repository/run/attempt/head SHA/event/branch/workflow metadata,
not these selected hashes or an in-container self-report. No merge or deployment.

- [x] G1: Failure contracts reject unsafe metadata and incorrect fail policies
  CHECK: python -B -m pytest tests/test_pii_shield_failure_contract.py -q -p no:cacheprovider
  EXPECT: /^[0-9]+ passed(?:, [0-9]+ warnings?)? in [0-9.]+s$/m
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=D:\Projects\_gs-action-integration-20260908; path=6cddee25275e/79 entries; EXPECT=matched; output-sha256=96f6c55c9b28f717aa45dbf11f0c229b4b91d48981a914b0b0d8f19366010abd; output-bytes=101

- [x] G2: Fatal-result, zones and entrypoint PII behavior remain compatible
  CHECK: python -B -m pytest tests/test_pii_shield_fatal_result.py tests/test_pii_shield.py tests/test_wasm_only_no_http.py tests/test_pii_zone_reconstruction.py tests/test_entrypoint_pii_shield.py -q -p no:cacheprovider
  EXPECT: /^[0-9]+ passed(?:, [0-9]+ warnings?)? in [0-9.]+s$/m
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=D:\Projects\_gs-action-integration-20260908; path=6cddee25275e/79 entries; EXPECT=matched; output-sha256=c5c17c8c384c6512456d47a550af692ffddf9f69118548441655e208154f6438; output-bytes=102

- [ ] G3: Independent reviewers approve the exact source and fail-first oracle
  EVIDENCE: pending

- [ ] G4: Independently confined Linux execution passes against the reviewed commit
  EVIDENCE: pending

- [x] G5: Removing the fatal guard fails the exact collision control
  CHECK: python -B docs/operations/adapter-failure-20260908/verify_marker_mutation.py
  EXPECT: FATAL_GUARD_REMOVAL_REJECTED
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=D:\Projects\_gs-action-integration-20260908; path=6cddee25275e/79 entries; EXPECT=matched; output-sha256=b06f33253d2ab20fc0dccb91e565c385758bc5141d328694887a5788d22a6749; output-bytes=954
