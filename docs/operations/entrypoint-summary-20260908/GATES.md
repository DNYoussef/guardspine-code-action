# Gates: immutable stage summaries and saved bundle ordering

OWNS: entrypoint.py, tests/test_entrypoint_summary_integrity.py, docs/operations/entrypoint-summary-20260908/**, docs/operations/fatal-result-20260908/verify_linux.py

Scope: first prerequisite of entrypoint reporting: later stage recording must
not mutate historical snapshots; saved bundle metadata includes its own stage
before signing. Base ca06c66. Three build rounds, two source review rounds.
Post-scan refresh must not restore strings removed by sanitization.
Console failure reporting remains the next leaf, not omitted. Full-document
redaction changing hashed content is a separately reproduced open blocker.
No merge, deployment, package change, or A2 closure.
This is the explicitly active leaf; earlier ledgers describe their named
commits. The unchanged candidate workflow runs the updated confined verifier.
Full candidate identity is the reviewed Git tree plus externally verified
GitHub commit/run/attempt/branch/workflow, not the selected byte controls alone.
The local schema at guardspine-spec commit 4b21006 rejects additional summary
fields; this leaf adds no schema fields and changes no exception policy.

- [x] G1: Stage snapshots and persisted signed bundle retain valid history and current metadata
  CHECK: python -B -m pytest tests/test_entrypoint_summary_integrity.py -q -p no:cacheprovider
  EXPECT: /^[0-9]+ passed(?:, [0-9]+ warnings?)? in [0-9.]+s$/m
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=D:\Projects\_gs-action-integration-20260908; path=90b59c67095c/79 entries; EXPECT=matched; output-sha256=3334c54213f2d163d59e7d1ac52a0e591048ffcaeff7fcb125d656a11e8d6eb8; output-bytes=100

- [x] G2: Existing entrypoint and anti-forgery behavior remains intact
  CHECK: python -B -m pytest tests/test_entrypoint_pii_shield.py tests/test_antiforgery.py -q -p no:cacheprovider
  EXPECT: /^[0-9]+ passed(?:, [0-9]+ warnings?)? in [0-9.]+s$/m
  EVIDENCE: exit=0; shell=C:\WINDOWS\system32\cmd.exe; cwd=D:\Projects\_gs-action-integration-20260908; path=90b59c67095c/79 entries; EXPECT=matched; output-sha256=9d85938b18f0b19320322c944b571cead63093a02bb5103e3d26a90cf5664d60; output-bytes=101

- [ ] G3: Independent Opus HIGH and Gemini HIGH approve the exact source and falsifiable tests
  EVIDENCE: pending

- [ ] G4: Independently confined Linux executes the reviewed candidate successfully
  EVIDENCE: pending
