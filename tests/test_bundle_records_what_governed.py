"""GATE: the bundle records what actually governed, not what was asked for.

Written by the auditor before the implementation.

THE DEFECT. The evidence bundle carries no governing-rubric identity at all.
create_bundle emits context / events / items / immutability_proof / summary /
sanitization / analysis_snapshot, and none of them name a rubric. The only
rubric identity captured anywhere is multi_model_review.rubric_name, which is
the `rubric:` INPUT string -- so when governance comes from
.guardspine/config.yml rubric_packs (the path the dashboard writes), the input
is still "default" and the bundle's only named rubric says "default" while
HIPAA governed the prompts and the evaluator.

Three ways that goes wrong today, all silent:
  * a pack that governed and found nothing leaves NO trace -- per-finding
    source_pack only exists for rules that fired
  * a pack named in config that could not be loaded is skipped with a CI-log
    warning; the bundle says nothing
  * when no configured pack loads, the scan falls back to the `rubric:` input
    and governs with those rules; the bundle says nothing about the fallback

So an auditor asking "show me HIPAA governed this change" gets a bundle that
can neither confirm it nor refute it. For a product whose entire claim is that
the record is recomputable, that is the claim itself unmet.

WHERE IT MUST LIVE, and why that matters. _compute_bundle_hash covers every
top-level key except bundle_hash and signatures, and seal_bundle is the LAST
step. A governance section added BEFORE sealing is therefore covered by the
whole-bundle hash and the signature, and verify_bundle_chain detects tampering.
Note that guardspine_kernel.verify_bundle does NOT check bundle_hash -- it
validates the item chain -- so "the kernel still verifies it" is NOT evidence
that the section is protected. The probe below tampers with the section and
requires verify_bundle_chain to notice.

TWO TRAPS FOUND WHILE CHECKING THE PLAN, both pinned below:
  1. RiskClassifier assigns `self.config_packs = []` on the fallback path, so
     reading config_packs after load reports "nothing was requested" in exactly
     the case where the requested list is the interesting fact.
  2. rubric_prompt_packs() yields DISPLAY names ("HIPAA Security Safeguards").
     A record keyed on display names cannot be compared to the config file the
     dashboard wrote, which is the whole point of recording it.
"""

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from src.risk_classifier import RiskClassifier


def _governance(classifier, rubric_input="default"):
    """The contract: one place builds the record, from the classifier.

    The builder must expose it as
    bundle_generator.build_governance_record(classifier, rubric_input=...)
    returning a dict, so entrypoint has no second opinion about what governed.
    """
    from src.bundle_generator import build_governance_record

    return build_governance_record(classifier, rubric_input=rubric_input)


# ---------------------------------------------------------------------------
# What the record must contain
# ---------------------------------------------------------------------------

def test_the_catalogue_version_is_recorded():
    """Two exact-pinned copies of the catalogue exist (dashboard + Action). The
    version is what makes a skew diagnosable instead of invisible."""
    import guardspine_prompts

    rec = _governance(RiskClassifier(config_packs=["security"]))
    assert rec["catalogue_version"] == guardspine_prompts.__version__


def test_a_pack_that_governed_and_found_nothing_is_still_recorded():
    """The gap that per-finding source_pack cannot close."""
    rec = _governance(RiskClassifier(config_packs=["hipaa-safeguards"]))
    assert "hipaa-safeguards" in rec["loaded_packs"], (
        "a pack that governed is absent from the record unless one of its "
        "rules happened to fire"
    )


def test_loaded_packs_are_ids_not_display_names():
    """It has to be comparable to the config file the dashboard wrote."""
    rec = _governance(RiskClassifier(config_packs=["hipaa-safeguards"]))
    assert rec["loaded_packs"] == ["hipaa-safeguards"], (
        f"expected stable ids, got {rec['loaded_packs']}"
    )


def test_a_skipped_pack_is_recorded_with_its_reason():
    """Today this is a ::warning:: in a CI log nobody reads."""
    rec = _governance(RiskClassifier(
        config_packs=["hipaa-safeguards", "not-a-real-pack"]))

    assert "not-a-real-pack" in rec["skipped_packs"], "the skip is unrecorded"
    reason = rec["skipped_packs"]["not-a-real-pack"]
    assert reason and "not-a-real-pack" in reason, (
        f"the skip carries no usable reason: {reason!r}"
    )
    assert "hipaa-safeguards" in rec["loaded_packs"]


def test_the_requested_list_survives_a_fallback():
    """TRAP 1. RiskClassifier sets self.config_packs = [] when no configured
    pack loads, so the requested list is destroyed precisely when a fallback
    makes it the most important thing to know."""
    rec = _governance(RiskClassifier(config_packs=["not-a-real-pack"]))

    assert rec["requested_packs"] == ["not-a-real-pack"], (
        "the record forgot what the repo actually asked for; "
        f"got {rec['requested_packs']}"
    )
    assert rec["fallback_applied"] is True, (
        "the scan governed with something other than what was requested and "
        "the record does not say so"
    )


def test_the_rubric_input_is_recorded_separately_from_the_packs():
    """`rubric:` and rubric_packs are different governance sources; conflating
    them is how the bundle came to say "default" while HIPAA governed."""
    rec = _governance(RiskClassifier(config_packs=["security"]),
                      rubric_input="default")
    assert rec["rubric_input"] == "default"
    assert rec["loaded_packs"] == ["security"]


def test_an_ungoverned_scan_says_so_rather_than_implying_packs():
    rec = _governance(RiskClassifier(rubric="default"))
    assert rec["requested_packs"] == []
    assert rec["fallback_applied"] is False


# ---------------------------------------------------------------------------
# It must be IN the sealed material, not decorative
# ---------------------------------------------------------------------------

def _sealed_bundle_with_governance(governance=None):
    """A REAL bundle, built the way the codebase builds one.

    Uses create_bundle rather than the kernel cross-verification fixture: that
    fixture carries no `events`, and verify_bundle_chain -- the only verifier
    that checks bundle_hash -- refuses a bundle with none. The kernel's
    verify_bundle would have accepted it, which is exactly why it is the wrong
    oracle for this property.
    """
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from src.bundle_generator import BundleGenerator

    pr = SimpleNamespace(
        number=42, title="Stub PR", created_at=datetime.now(timezone.utc),
        user=SimpleNamespace(login="stub-user"),
        base=SimpleNamespace(ref="main"), head=SimpleNamespace(ref="feature"),
    )
    analysis = {"files_changed": 1, "lines_added": 4, "lines_removed": 0,
                "sensitive_zones": [], "files": []}
    risk_result = {"risk_tier": "L1", "risk_drivers": [], "findings": [],
                   "rationale": "stub", "decision": "merge"}

    generator = BundleGenerator()
    bundle = generator.create_bundle(
        pr=pr, analysis=analysis, risk_result=risk_result,
        repository="test/repo", commit_sha="abc1234567890",
    )
    bundle["governance"] = governance or {
        "catalogue_version": "0.2.0",
        "requested_packs": ["hipaa-safeguards"],
        "loaded_packs": ["hipaa-safeguards"],
        "skipped_packs": {},
        "rubric_input": "default",
        "fallback_applied": False,
    }
    generator.seal_bundle(bundle, strip_signatures=True)
    return bundle


def test_tampering_with_the_governance_record_is_detected():
    """The load-bearing probe. A governance section the seal does not cover is
    worse than none: it reads as evidence and is forgeable.

    NOTE: guardspine_kernel.verify_bundle passes either way -- it checks the
    item chain, not bundle_hash -- so it must NOT be used as the oracle here.
    """
    from src.bundle_generator import verify_bundle_chain

    good = _sealed_bundle_with_governance()
    # verify_bundle_chain returns (ok, reason), not a dict.
    ok, reason = verify_bundle_chain(good)
    assert ok, f"a sealed bundle must verify: {reason}"

    forged = copy.deepcopy(good)
    forged["governance"]["loaded_packs"] = ["pci-dss-requirements"]
    ok_forged, _ = verify_bundle_chain(forged)

    assert not ok_forged, (
        "the governance record can be rewritten after sealing without "
        "invalidating the bundle -- it is decoration, not evidence"
    )


def test_the_bundle_still_verifies_under_the_kernel():
    """Counterweight: adding a section must not break cross-verification."""
    from guardspine_kernel.verify import verify_bundle

    assert verify_bundle(_sealed_bundle_with_governance())["valid"]


def test_the_real_create_bundle_path_seals_the_record():
    """Audit addition. The probe above seals a governance section by hand, so
    it proves the SEAL covers such a section -- not that create_bundle puts it
    inside the seal. If create_bundle attached it after sealing, every probe
    above would still pass and the record would be forgeable.
    """
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from src.bundle_generator import (
        BundleGenerator, build_governance_record, verify_bundle_chain,
    )

    classifier = RiskClassifier(config_packs=["hipaa-safeguards"])
    pr = SimpleNamespace(
        number=7, title="t", created_at=datetime.now(timezone.utc),
        user=SimpleNamespace(login="u"),
        base=SimpleNamespace(ref="main"), head=SimpleNamespace(ref="f"),
    )
    bundle = BundleGenerator().create_bundle(
        pr=pr,
        analysis={"files_changed": 1, "lines_added": 1, "lines_removed": 0,
                  "sensitive_zones": [], "files": []},
        risk_result={"risk_tier": "L1", "risk_drivers": [], "findings": [],
                     "rationale": "r", "decision": "merge"},
        repository="test/repo", commit_sha="deadbeefcafe",
        governance=build_governance_record(classifier, rubric_input="default"),
    )

    assert bundle["governance"]["loaded_packs"] == ["hipaa-safeguards"]
    ok, reason = verify_bundle_chain(bundle)
    assert ok, f"a freshly created bundle must verify: {reason}"

    bundle["governance"]["loaded_packs"] = ["security"]
    ok_forged, _ = verify_bundle_chain(bundle)
    assert not ok_forged, (
        "create_bundle attached the governance record OUTSIDE the seal -- it "
        "can be rewritten without invalidating the bundle"
    )
