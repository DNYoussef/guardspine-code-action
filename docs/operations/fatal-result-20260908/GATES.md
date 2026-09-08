# Gates: observable engine fatal return

OWNS: src/pii_shield.py, tests/test_pii_shield_fatal_result.py, tests/test_pii_shield_decimal_regression.py, .github/workflows/candidate-fatal-result.yml, docs/operations/fatal-result-20260908/**

Scope: Reject the exact whole-output package fatal marker at the shared adapter
boundary. Always request closed engine policy so errors stay observable, then
apply caller policy in sanitize_text. Preserve embedded literals and explicit
fail-open policy. Exact whole-input sentinel collisions fail closed. No dependency
change, diff normalization, zero-pointer fix, Action merge or native crash claim.
Inherited integration and native-crash gates remain open. Tier T3 continues;
this is the first implementation after integration plan review round one.

- [ ] G1: Fatal return handling and literal compatibility controls pass
  CHECK: C:/Users/17175/.codex-work/gs-action-integration-20260908/venv/Scripts/python.exe -m pytest tests/test_pii_shield_fatal_result.py -q
  EXPECT: /^24 passed in [0-9.]+s$/m
  EVIDENCE: pending

- [ ] G2: Existing adapter behavior and published-package guarantees remain intact
  CHECK: C:/Users/17175/.codex-work/gs-action-integration-20260908/venv/Scripts/python.exe -m pytest tests/test_pii_shield.py tests/test_wasm_only_no_http.py -q
  EXPECT: /^30 passed in [0-9.]+s$/m
  EVIDENCE: pending

- [ ] G3: Independent source review and confined Linux execution accept the exact candidate
  EVIDENCE: pending

The gate-check runner requires exit status zero AND an EXPECT match
(gate-check.mjs:599); EXIT is not a supported ledger attribute. These CHECKs
name the owned Windows interpreter; Linux verifies the same test paths with
its own recorded Python executable and hash-installed dependencies. Windows
evidence does not satisfy G3. Entrypoint presentation of fail-open warnings is
a separate integration gate, not certified by this adapter-only unit.

G3 source identity is judged OUTSIDE the candidate runtime. A success banner
alone is never acceptance. The six hashes in verify_linux.py are narrow byte
controls, not a complete source manifest or self-attestation of the verifier.
The source boundary is the complete Git tree of one finalized candidate commit,
with its finite reviewed delta from baseline c38e05439296199cb776898704abbb13bb3b622a.

Before publication, require a clean committed checkout and reconcile its delta
against exactly these reviewed paths: src/pii_shield.py, both new PII test files,
this GATES.md, Dockerfile.verify, verify_linux.py, and candidate-fatal-result.yml.
Verify committed blob bytes against the six EXPECTED values and record commit
and tree IDs in the external run evidence, not recursively inside that commit.
Reject any additional changed, deleted, untracked or symlink path. Source and
verifier authors cannot approve their own artifacts.

After publication, fetch GitHub's authoritative run metadata independently of
container stdout. Require repository DNYoussef/guardspine-code-action, event push,
branch candidate/action-integration-20260908, workflow path
.github/workflows/candidate-fatal-result.yml, the exact recorded head_sha, and
the inspected run ID/attempt with successful conclusion and verifier step.
Reject wrong-SHA and wrong-workflow records even with a matching success banner;
exercise these known-bad controls before accepting the metadata check. Confirm
no other workflow ran for the candidate commit. Inspect matching checkout SHA,
confinement controls, runtime/package versions, six byte controls, and exactly
54 non-skipped/non-failing/non-error cases from that same run and attempt.
Record the GitHub URL and independent reviewer identities. GitHub's control
plane, pinned checkout action and reviewed workflow are explicit trust anchors.
Any new commit or source edit invalidates acceptance until reviewed again.

This candidate remains push-only and unaccepted before those checks: no PR,
merge, deployment, application secrets or broader integration closure. The
decimal suite is excluded and NOT RUN here; its technical gate remains required.
