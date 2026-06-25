"""
Crucible fail-first gates for the two fact-check fixes:
  Fix 1 -- a keyless bundle_hash seals the WHOLE bundle (tamper any top-level
           field -> verification fails). Today only items are chained.
  Fix 2 -- compliance rubric findings carry the control category + name through
           to the finding dict (today dropped -> receipt shows "general").

Both are written to FAIL before the implementation and pass after. Run:
  python -m pytest tests/test_factcheck_fixes.py -q
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from pathlib import Path

from src.bundle_generator import BundleGenerator, verify_bundle_chain
from src.risk_classifier import RiskClassifier, Finding

ROOT = Path(__file__).resolve().parents[1]


def _stub_pr():
    return SimpleNamespace(
        number=7,
        title="test PR",
        created_at=datetime(2026, 6, 24, tzinfo=timezone.utc),
        user=SimpleNamespace(login="tester"),
        base=SimpleNamespace(ref="main"),
        head=SimpleNamespace(ref="feature"),
    )


def _make_bundle():
    gen = BundleGenerator()
    analysis = {
        "files_changed": 2, "lines_added": 10, "lines_removed": 1,
        "sensitive_zones": [], "diff_hash": "abc", "multi_model_review": {},
    }
    risk_result = {
        "risk_tier": "L2", "findings": [], "risk_drivers": [],
        "rationale": "x", "decision": "merge",
    }
    return gen.create_bundle(
        pr=_stub_pr(), analysis=analysis, risk_result=risk_result,
        repository="owner/repo", commit_sha="deadbeef",
    )


# --- Fix 1 -------------------------------------------------------------------
def test_producer_stamps_bundle_hash():
    bundle = _make_bundle()
    assert "bundle_hash" in bundle and bundle["bundle_hash"].startswith("sha256:")


def test_tampering_top_level_field_breaks_verification():
    bundle = _make_bundle()
    ok, _ = verify_bundle_chain(bundle)
    assert ok, "freshly produced bundle should verify"
    # summary sits OUTSIDE the item chain today -- tampering must now be caught
    bundle["summary"]["decision"] = "merge_FORGED"
    ok, msg = verify_bundle_chain(bundle)
    assert not ok and "bundle_hash" in msg.lower()


# --- Fix 2 -------------------------------------------------------------------
def test_rubric_rule_carries_control_metadata():
    rc = RiskClassifier(rubric="soc2", repo_root=ROOT)
    rule = next((r for r in rc.rubric_rules if r["id"] == "SOC2-CC6.1"), None)
    assert rule is not None, "SOC2-CC6.1 rule should load"
    assert rule.get("control_category") == "CC-AccessControl"
    assert rule.get("control_name") == "Change Management"


def test_finding_dict_includes_control_label():
    rc = RiskClassifier(rubric="soc2", repo_root=ROOT)
    f = Finding(
        id="RUBRIC-SOC2-CC6.1", severity="high", message="m", file="a.py",
        line=1, rule_id="SOC2-CC6.1",
        control_category="CC-AccessControl", control_name="Change Management",
    )
    d = rc._finding_to_dict(f)
    assert d["control_category"] == "CC-AccessControl"
    assert d["control_name"] == "Change Management"


def test_deleting_bundle_hash_is_rejected():
    # Closes the downgrade bypass: a v0.2.0 bundle (has immutability_proof) with
    # bundle_hash stripped must NOT fall back to event-only verification.
    bundle = _make_bundle()
    del bundle["bundle_hash"]
    ok, msg = verify_bundle_chain(bundle)
    assert not ok and "bundle_hash" in msg.lower()


def test_mutation_after_seal_detected_then_reseal_fixes():
    bundle = _make_bundle()
    bundle["analysis_snapshot"]["sanitization"] = {"redaction_count": 3}  # post-seal mutation
    ok, _ = verify_bundle_chain(bundle)
    assert not ok, "mutation after seal must be caught"
    BundleGenerator().seal_bundle(bundle)  # re-seal the final bytes
    ok, msg = verify_bundle_chain(bundle)
    assert ok, msg


def test_signed_bundle_self_verifies():
    gen = BundleGenerator()
    analysis = {"files_changed": 1, "lines_added": 1, "lines_removed": 0,
                "sensitive_zones": [], "diff_hash": "abc", "multi_model_review": {}}
    risk = {"risk_tier": "L2", "findings": [], "risk_drivers": [],
            "rationale": "x", "decision": "merge"}
    bundle = gen.create_bundle(
        pr=_stub_pr(), analysis=analysis, risk_result=risk,
        repository="owner/repo", commit_sha="deadbeef",
        attestation_key="hmac-fallback-key", allow_insecure_signature_fallback=True,
    )
    assert len(bundle["signatures"]) == 1
    ok, msg = verify_bundle_chain(bundle)
    assert ok, msg


def test_entrypoint_map_findings_carries_control_label():
    from entrypoint import _map_findings
    out = _map_findings([{
        "severity": "high", "message": "change touches access control",
        "rule_id": "SOC2-CC6.1", "file": "src/auth.py", "line": 12,
        "control_category": "CC-AccessControl", "control_name": "Change Management",
    }])
    assert out[0].category == "CC-AccessControl"          # not "general"
    assert "Change Management" in out[0].description


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print("PASS", fn.__name__)
        except Exception as e:
            failed += 1
            print("FAIL", fn.__name__, "->", type(e).__name__, e)
    sys.exit(1 if failed else 0)
