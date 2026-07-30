"""GATE: an unsigned evidence bundle says so. It never passes as a signed one.

Written by the auditor before the change.

THE DEFECT, observed live rather than theorised. The GuardSpine self-scan ran
on 2026-07-30 (run 30478597721) and produced bundle-pr252-61baf12.json with
`"signatures": []`. Nothing in the run said so. The cause is not a bad key --
`pr-check.yml` never passes attestation_key at all, and the repo has no
GUARDSPINE_ATTESTATION_KEY secret. seal_bundle reads:

    if attestation_key:
        bundle["signatures"].append(...)

so a falsy key produces an unsigned bundle in silence, and the run is green.

WHY THAT MATTERS MORE THAN IT LOOKS. Two tiers exist by design and the
docstring in seal_bundle is explicit about it: the keyless bundle_hash gives
tamper-EVIDENCE (anyone can recompute it), while a signature gives
NON-REPUDIATION (only the holder of the private key could have produced it).
Those are different claims to an auditor. A bundle that silently delivers the
weaker one, while the workflow reports "Evidence bundle generated" and uploads
it as a 90-day artifact, invites the reader to assume the stronger one.

WHAT IS DELIBERATELY NOT CHANGED. Unsigned bundles stay legal and stay
non-fatal. Signing needs a private key that only the repo owner can install,
and hard-failing every unsigned run would break every consumer who never opted
into attestation. The property here is honesty, not enforcement.

SCOPE NOTE. The JSON already tells the truth -- `signatures: []` is
unambiguous to anything that parses it. The silence is on the human- and
workflow-facing surface, so that is the only surface this gate binds.

CONTRACT. entrypoint exposes a strict verdict helper, mirroring the existing
_bundle_sync_failed:

    _bundle_is_signed(bundle) -> bool

and the bundle step publishes it as the `bundle_signed` output so a workflow
can branch on it, plus emits a ::warning:: when it is false.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import entrypoint


# ---------------------------------------------------------------------------
# The verdict, strict in the same way _bundle_sync_failed is strict
# ---------------------------------------------------------------------------

def test_the_signed_verdict_is_strict():
    """Only a non-empty signatures list counts as signed. Every other shape --
    absent, empty, null, or a non-list -- is unsigned, because 'we could not
    tell' must resolve to the weaker claim, never the stronger one."""
    f = entrypoint._bundle_is_signed

    assert f({"signatures": [{"public_key_id": "k1", "signature": "abc"}]}) is True

    assert f({"signatures": []}) is False       # the live case, run 30478597721
    assert f({}) is False                       # key absent entirely
    assert f({"signatures": None}) is False
    assert f({"signatures": "yes"}) is False    # truthy string is not a signature
    assert f({"signatures": 1}) is False        # truthy scalar is not a signature
    assert f(None) is False                     # no bundle at all


def test_an_unsigned_bundle_is_not_reported_as_signed_by_accident():
    """Guards the inversion. A helper that returned truthiness of the KEY
    rather than of the RESULT would pass every probe above while still lying
    about a run where signing was attempted and produced nothing."""
    attempted_but_empty = {"signatures": [], "bundle_hash": "sha256:abc"}
    assert entrypoint._bundle_is_signed(attempted_but_empty) is False


# ---------------------------------------------------------------------------
# The warning: it must name the tier, not merely mention signing
# ---------------------------------------------------------------------------

def test_an_unsigned_bundle_produces_a_github_warning():
    notice = entrypoint._attestation_notice({"signatures": []})
    assert notice is not None, "an unsigned bundle is still emitted in silence"
    assert notice.startswith("::warning::"), (
        f"the notice is not a GitHub annotation, so it will not surface in the "
        f"run summary: {notice!r}"
    )


def test_the_warning_states_which_claim_is_missing():
    """A warning saying only 'not signed' is nearly as useless as silence: the
    reader cannot tell whether the bundle is worthless or merely the weaker
    tier. It must distinguish tamper-evidence from non-repudiation."""
    notice = entrypoint._attestation_notice({"signatures": []}).lower()

    assert "non-repudiation" in notice or "non-repudiable" in notice, (
        "the warning does not name the claim that is absent"
    )
    assert "hash" in notice or "tamper" in notice or "integrity" in notice, (
        "the warning does not say what the bundle DOES still prove, so it reads "
        "as 'this evidence is void' rather than 'this is the weaker tier'"
    )
    assert "attestation_key" in notice, (
        "the warning does not name the input that fixes it"
    )


def test_a_signed_bundle_produces_no_warning():
    """Counterweight. A warning on every run is a warning nobody reads -- the
    exact failure the Lane G calibration comment in pr-check.yml describes."""
    signed = {"signatures": [{"public_key_id": "k1", "signature": "abc"}]}
    assert entrypoint._attestation_notice(signed) is None


# ---------------------------------------------------------------------------
# It has to be machine-readable, not only human-readable
# ---------------------------------------------------------------------------

def test_the_signed_state_is_published_as_a_step_output():
    """A log line cannot be gated on. The workflow that uploads the bundle as a
    90-day artifact must be able to branch on whether it is non-repudiable, so
    the state belongs in the step outputs next to bundle_path / bundle_id.

    Asserts the emitted GITHUB_OUTPUT bytes rather than the print, because the
    output file is the actual contract with the workflow.
    """
    import os
    import tempfile

    for signatures, expected in (([], "false"),
                                 ([{"public_key_id": "k", "signature": "s"}], "true")):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "gh-output"
            out.write_text("", encoding="utf-8")
            os.environ["GITHUB_OUTPUT"] = str(out)
            try:
                entrypoint.set_output(
                    "bundle_signed",
                    "true" if entrypoint._bundle_is_signed({"signatures": signatures})
                    else "false",
                )
            finally:
                os.environ.pop("GITHUB_OUTPUT", None)

            written = out.read_text(encoding="utf-8")
            assert "bundle_signed" in written
            assert f"\n{expected}\n" in written, (
                f"expected bundle_signed={expected}, file was: {written!r}"
            )
