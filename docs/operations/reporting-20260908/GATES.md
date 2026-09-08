# Gates: truthful sanitization failure reporting

OWNS: entrypoint.py, tests/test_entrypoint_failure_reporting.py, docs/operations/reporting-20260908/**, docs/operations/fatal-result-20260908/verify_linux.py, .github/workflows/candidate-fatal-result.yml

Scope: Finite privacy-safe failure labels, honest non-scan summaries, unchanged exit policies, actual entrypoint publication checks. Bundle producer hash ordering is the next required leaf, not covered here. No merge or deployment.

This is the active ledger for these paths. entrypoint-summary-20260908 is
historical; its snapshot acceptance is recorded externally. After failed CI
34287459941, Fable HIGH and Astra xhigh RCA required the canonical pin preflight
below. Recovery budget: two build rounds and two independent source rounds,
explicitly additional to the exhausted initial budget, not a reset. G1/G2's
recorded evidence below remains historical until fresh execution is recorded.

- [ ] G1: Reporting tests prove real adapter marker binding, sticky immutable summaries, entrypoint privacy and publication consequences, and preserved fatal policies.
  CHECK: python docs/operations/reporting-20260908/verify_reporting.py reporting
  EXPECT: REPORTING_REPORTING_VERIFIED
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=D:\Projects\_gs-action-integration-20260908; path=9096563fa234/79 entries; EXPECT=matched; output-sha256=2b09bc3f5c15c779f70fa3d9eb0de0f9171364af223330dfa43eca15a1083ef2; output-bytes=751

- [ ] G2: Prior summary, caller, and adapter contracts remain green.
  CHECK: python docs/operations/reporting-20260908/verify_reporting.py regressions
  EXPECT: REPORTING_REGRESSIONS_VERIFIED
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=D:\Projects\_gs-action-integration-20260908; path=9096563fa234/79 entries; EXPECT=matched; output-sha256=ce27e8837f2bfd4d93769ec54746b0d1525ff13783edcd8e3b2020b3360be28e; output-bytes=136

- [ ] G3: Independent Opus HIGH and Gemini HIGH source audits accept the same immutable complete snapshot; author excluded from verifiers.
  EVIDENCE: pending

- [ ] G4: Independently confined Linux CI reproduces both contracts on the exact published unaccepted candidate commit; repository/run/workflow/attempt identity verified.
  EVIDENCE: pending

- [ ] G5: All reviewed verifier pins match the immutable staged Git tree before publication, with no unstaged tracked changes.
  CHECK: python docs/operations/reporting-20260908/check_blob_pins.py
  EXPECT: GIT_BLOB_PINS_VERIFIED 14
  EVIDENCE: pending

- [ ] G6: The same pin comparator accepts canonical bytes and rejects changed pins, CRLF substitution, missing files and empty maps.
  CHECK: python docs/operations/reporting-20260908/test_blob_pins.py
  EXPECT: BLOB_PIN_CONTROLS_VERIFIED
  EVIDENCE: pending
