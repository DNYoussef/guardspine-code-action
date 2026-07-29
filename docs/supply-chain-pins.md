# Supply-chain pins

Last refreshed: 2026-06-12.

This project pins third-party GitHub Actions by full commit SHA, Python runtime
and CI dependencies by `pip-compile --generate-hashes`, and the Docker Python
base by manifest digest.

## GitHub Actions

| Workflow reference | Tag reviewed | Commit |
| --- | --- | --- |
| `actions/checkout` | `v4` | `34e114876b0b11c390a56381ad16ebd13914f8d5` |
| `actions/setup-python` | `v5` | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| `docker/setup-buildx-action` | `v3` | `8d2750c68a42422c14e847fe6c8ac0403b4cbd6f` |
| `docker/login-action` | `v3` | `c94ce9fb468520275223c153574b00df6fe4bcc9` |
| `docker/metadata-action` | `v5` | `c299e40c65443455700f0fdfc63efafe5b349051` |
| `docker/build-push-action` | `v6` | `10e90e3645eae34f1e60eeb005ba3a3d33f178e8` |
| `actions/upload-artifact` | `v4` | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `github/codeql-action/upload-sarif` | `v3` | `b0c4fd77f6c559021d78430ec4d0d169ae74a4eb` |

`DNYoussef/guardspine-code-action@v2` in the dogfood workflow is first-party and
intentionally remains a consumer-contract rehearsal of the published action.

## The action's own image pin

`action.yml` on a release tag pins the runtime image. Through v2.7.1 that was a
TAG:

    image: 'docker://ghcr.io/dnyoussef/guardspine-code-action:2.7.1'

A registry tag is mutable. Re-pushing `2.7.1` would silently change what every
consumer pinned to `@v2.7.1` executes, while the Dockerfile one directory away
digest-pins its own base image. For a product whose subject is supply-chain
governance, holding ourselves to a weaker standard than we hold the base image
is not a defensible asymmetry.

From v2.7.2 the image is pinned by DIGEST, which cannot be repointed:

    image: 'docker://ghcr.io/dnyoussef/guardspine-code-action@sha256:4b978fb4...'

`main` keeps `image: 'Dockerfile'` so CI and the dryrun job build from the
source under test. Releases are cut from a `release/` branch that flips it to
the digest -- v2.7.0 was tagged straight off main and therefore rebuilds from
source on every consumer run, which is why it is superseded.

## Docker base image

`python:3.11-slim` is pinned to:

`sha256:f9fa7f851e38bfb19c9de3afbc4b86ae7176ea7aaf94535c31df5458d5849457`

This is the OCI index digest reported by `docker buildx imagetools inspect
python:3.11-slim` on 2026-06-12.

## Python dependencies

`requirements.in` is the editable runtime dependency floor file.
`requirements.txt` is the generated runtime lock with hashes.

`requirements-ci.in` is the editable CI/test dependency floor file.
`requirements-ci.txt` is the generated CI/test lock with hashes.

Refresh command:

```bash
python -m piptools compile --strip-extras --generate-hashes --resolver=backtracking --output-file requirements.txt requirements.in
python -m piptools compile --strip-extras --generate-hashes --resolver=backtracking --output-file requirements-ci.txt requirements-ci.in
```

## Known residual

The Dockerfile still installs Debian `git` through `apt`. Full Debian snapshot
pinning is not part of this PR; this pass pins the surfaces called out in Phase
6.2: GitHub Actions, Python dependencies, and the Docker base image.
