# Gates: producer bundle sanitization before hashing

Scope: validated producer draft, truthful accounting, valid final proofs.
Budget: user-authorized continuing cycles; record each revision and failed attempt.
After the original two-review-round budget, Fable HIGH and Astra extra-high RCA
is required before further corrections. RCA is supporting analysis, not approval.
Authorship: Codex builder; independent Opus HIGH and Gemini HIGH source audits.
Python 3.11 with the existing locked dependencies. No local Docker.
G1/G2 compare collected and executed inventories; file contents and therefore
test deletion are pinned by G3/G5. Neither standalone suite proves snapshot identity.
The selected pins are not a transitive dependency manifest. G4/G5 additionally
require reconciliation of the complete reviewed Git tree with the executed SHA.

- [ ] G1: real redaction preserves signed bundle integrity and rejects structural corruption
  CHECK: python -B docs/operations/bundle-ordering-20260908/verify_bundle_ordering.py
  EXPECT: BUNDLE_ORDERING_VERIFIED
  EVIDENCE: pending

- [ ] G2: reporting and producer regressions pass with only the existing named consent xfail
  CHECK: python -B docs/operations/bundle-ordering-20260908/verify_bundle_ordering.py regressions
  EXPECT: BUNDLE_REGRESSIONS_VERIFIED
  EVIDENCE: pending

- [ ] G3: canonical source pins match immutable Git blobs
  CHECK: python -B docs/operations/reporting-20260908/check_blob_pins.py
  EXPECT: GIT_BLOB_PINS_VERIFIED
  EVIDENCE: pending

- [ ] G4: final source is approved by eligible independent reviewers
  EVIDENCE: pending

- [ ] G5: exact candidate executes the same gates in independently confined Linux CI
  EVIDENCE: pending

  External acceptance must bind run, workflow, attempt, candidate SHA and successful
  confined step, then require every G1/G2 EXPECT token and the existing consent-xfail
  disclosure in the captured CI log. A successful job exit alone is insufficient.
  A wrong-SHA control and a copied log with each required marker removed must fail
  the same external evidence check before accepting the actual run.
