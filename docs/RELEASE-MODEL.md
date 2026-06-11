# Release Model (current contract + target proposal)

Status: PROPOSAL for review. This document changes no behavior. It does not
move the `v1` tag, change `action.yml`, or touch detector logic. It documents
the current release contract, proposes a target, and gives a staged migration
plan with a consumer rehearsal gate.

Verified facts (2026-06-11) are in the Appendix.

## 1. Current contract (as-is)

The chain a consumer actually traverses:

1. A consumer references `DNYoussef/codeguard-action@v1`
   (GuardSpine uses it in `.github/workflows/pr-check.yml` and `dogfood.yml`).
2. GitHub resolves `@v1` to the **git tag** `v1` (currently commit `9147821`,
   which equals `v1.0.5`).
3. `action.yml` at that tag declares
   `runs.image: docker://ghcr.io/dnyoussef/codeguard-action:main`.
4. So every `@v1` run pulls the **mutable** `:main` image.
5. `docker-publish.yml` rebuilds and pushes `:main` on every push to `main`
   (the `type=ref,event=branch` tag).

Net effect: **`@v1` is effectively `@main-image`.** A merge to `main` reaches
every `@v1` consumer on their next run, with no tag move and no promotion
gate. This is exactly how P1, P2, and P3 reached consumers immediately.

Already published today but NOT referenced by `action.yml`:
- `:sha-<shortsha>` -- an immutable per-commit image tag on every push
  (`type=sha`). Immutable provenance already exists.
- `:X.Y.Z` and `:X` semver image tags -- but only on a `v*` tag push
  (`type=semver`). Releases are not currently cut as tag pushes, so these are
  stale (last built at `v1.0.5`).

### Risks of the as-is model
1. **Reproducibility:** `@v1` pins nothing. Two runs days apart can execute
   different code. A consumer cannot pin a known-good version.
2. **Misleading version tag:** the `v1` git tag (`9147821`) does not reflect
   the code that runs (main's Dockerfile build, published to `:main`).
   Auditing "what ran" requires the live `:main` digest, not the tag.
3. **Supply chain:** a bad or malicious merge to `main` reaches every consumer
   on the next run; there is no digest-pinned artifact and no consumer-side
   promotion gate.
4. **Rollback:** reverting a bad release means reverting `main` and waiting for
   the rebuild; consumers cannot pin back to a prior good version because none
   is wired into a reference.

Mitigations already in place: every PR is gated by CI
(unit/regression, eval-offline incl. the secrets gate, dryrun) and the
self-dogfood. These are **pre-merge** gates on what reaches `main`; they are
not consumer-side pinning or a release promotion step.

## 2. Target model proposal

Goal: a version reference resolves to fixed, auditable code, and releases are
deliberate -- while preserving a fast path for fixes.

Two viable shapes (not mutually exclusive):

### Option A (recommended): build from source at an immutable ref
- `action.yml` uses `runs.image: 'Dockerfile'` at every ref (main and tags).
  GitHub builds the image from the source at the exact ref it resolves to
  (GHA build cache mitigates cost). No dependency on a mutable image tag.
- A release is an immutable git tag `vX.Y.Z` at a reviewed commit. The
  floating major tag `vX` is moved to that commit (the canonical GitHub
  Action convention: `vX` floats to the latest `vX.*`, each `vX.Y.Z` is fixed).
- Consumers choose their pin:
  - `@vX.Y.Z` -- fully immutable (exact source).
  - `@vX` -- latest within major X; each `X.Y.Z` is itself deliberate.
  - `@<full-sha>` -- maximum pinning.
- Pros: fully reproducible from source; the git tag IS the running code; no
  mutable-image coupling; the model contributors already expect.
- Cons: each run builds the Docker image (first run per cache key is slower).

### Option B: immutable prebuilt image by tag/digest
- `action.yml` references `docker://...:X.Y.Z` or `...@sha256:<digest>` -- a
  prebuilt immutable image.
- A release builds + pushes `:X.Y.Z`, records the digest, and updates the
  tag's `action.yml` to that exact image.
- Consumers pin `@vX.Y.Z`.
- Pros: fast (pull prebuilt); strongest supply-chain story (digest).
- Cons: `action.yml` must be regenerated per release (the version/digest is
  baked in); more release machinery.

**Recommendation:** Option A as the baseline (simplest, reproducible, matches
the Actions ecosystem), with `docker-publish.yml` continuing to emit
`:X.Y.Z` / `:sha-*` images as an optional fast path and provenance record.
A digest pin (Option B) can be layered later for high-security consumers.

Either way the load-bearing change is the same: **sever the `@v1 -> :main`
mutable coupling** so a version reference resolves to fixed code.

## 3. Migration plan (staged; no blind v1 move)

Constraint: GuardSpine `@v1` currently resolves to `:main`. Any change to the
`v1` tag's `action.yml`, or a `v1` move, changes consumer behavior. Stage it so
consumers are never silently broken. (None of these steps are executed by this
document.)

- **Step 0 (prereq):** confirm `main` is green and is the intended `v1.1.0`
  (it carries P1/P2/P3). No action.
- **Step 1 -- cut a real immutable release at current main:** push git tag
  `v1.1.0` at `main` (`5d2afc9`). `docker-publish` builds `:1.1.0`, `:1`,
  `:sha-5d2afc9` immutable images. This creates the first pinnable release
  WITHOUT touching `v1` or any consumer.
- **Step 2 -- decide resolution (A vs B) and prepare on main:** if Option A,
  set `action.yml` `image: 'Dockerfile'` on `main` (so the next tag inherits
  it). This is itself a behavior-affecting change to HOW the action resolves,
  so it must be rehearsed (Step 3) before any consumer points at it. Keep it
  unreleased until rehearsed.
- **Step 3 -- rehearse the immutable path on GuardSpine BEFORE moving anything:**
  open a GuardSpine PR pinning `uses: DNYoussef/codeguard-action@v1.1.0` and run
  the two-directional rehearsal (Section 4). Proves the immutable tag resolves
  and behaves identically to the current `@v1`/`:main` path.
- **Step 4 -- move the floating `v1` tag (only after Step 3 passes):** move
  `v1` from `9147821` -> `5d2afc9` (== `v1.1.0`). Now `@v1` resolves to the
  `v1.1.0` `action.yml`; under Option A it builds from `v1.1.0` source and the
  `:main` coupling is severed. This is the one deliberate, reviewed tag move --
  not blind, because Step 3 already proved the target.
- **Step 5 -- update consumers + document:** update GuardSpine `pr-check.yml`
  and `dogfood.yml` to pin `@v1.1.0` (explicit immutable) or keep `@v1` (now
  backed by a real release). Recommend `@v1.1.0` for reproducibility; `@v1`
  only if auto-uptake of patch releases is wanted. Document the pin policy in
  both repos.
- **Step 6 -- ongoing release ritual:** releases are cut by pushing `vX.Y.Z`
  tags (not by merging to `main`); moving `vX` to the latest release is part of
  the ritual. `:main` stays a dev/preview image, never referenced by a version
  tag.

## 4. Rehearsal plan for GuardSpine consumers (the gate)

Mirror the P3 rehearsal exactly, against the CANDIDATE immutable ref before
promoting it:
- **RED:** a PR adding a private-key marker (or an unquoted AWS secret) ->
  CodeGuard `decision=block` -> Lane G red.
- **GREEN:** a PR adding a sha256 hash field + a placeholder + a UUID ->
  `decision=merge` -> Lane G green.
- Run BOTH pinned to the candidate ref (`@v1.1.0`) before moving `v1`. Promote
  only if both directions match the behavior already proven for `@v1`/`:main`
  (GuardSpine PRs #114 red and #115 green during the P3 cutover).
- Include `dogfood.yml` in the cutover: it also uses `@v1`.

## 5. Explicit non-goals (this task)
- No detector logic changes.
- No relicense entanglement -- the BSL work stays separate.
- `v1` is NOT moved here; this is the documented plan and proposal only.
- No consumer references changed yet.

## Appendix: verified facts (2026-06-11)
- `action.yml@main`: `runs.using: docker`, `image: 'Dockerfile'`.
- `action.yml@v1` (`9147821`): `image: 'docker://ghcr.io/dnyoussef/codeguard-action:main'`.
- `v1` git tag -> `9147821` (== `v1.0.5`).
- Tags present: `v1`, `v1.0.0` .. `v1.0.5`.
- `docker-publish.yml` triggers: push to `main`, push `v*` tags, release
  published. Emits: `type=ref,event=branch` (-> `:main`),
  `type=semver {{version}}` and `{{major}}`, `type=sha` (-> `:sha-<shortsha>`).
- GuardSpine consumers: `pr-check.yml:48` and `dogfood.yml:25`, both `@v1`.
- Current `main` head at time of writing: `5d2afc9` (carries P1/P2/P3).
