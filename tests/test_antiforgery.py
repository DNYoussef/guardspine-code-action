"""
Anti-forgery acceptance gate (crucible). A SIGNED bundle must be tamper-PROOF
against a malicious party, verified against a TRUSTED key/fingerprint. Seven
forge vectors must all be REJECTED; legit signed verifies; unsigned stays
integrity-only (tamper-evident).

API under test:
  verify_bundle_chain(bundle, trusted_fingerprints=None, trusted_keys=None,
                      require_signature=False) -> (bool, str)

Run: python -m pytest tests/test_antiforgery.py -q
"""

import base64
import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from src.bundle_generator import BundleGenerator, verify_bundle_chain
from src.canonical_json import canonical_json_dumps


def _gen_key():
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub = priv.public_key()
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = "sha256:" + hashlib.sha256(der).hexdigest()
    return priv, priv_pem, fingerprint


def _stub_pr(n=7):
    return SimpleNamespace(
        number=n, title="t", created_at=datetime(2026, 6, 24, tzinfo=timezone.utc),
        user=SimpleNamespace(login="u"), base=SimpleNamespace(ref="main"),
        head=SimpleNamespace(ref="f"),
    )


def _signed_bundle(priv_pem, commit="deadbeef", n=7):
    gen = BundleGenerator()
    analysis = {"files_changed": 1, "lines_added": 1, "lines_removed": 0,
                "sensitive_zones": [], "diff_hash": "abc", "multi_model_review": {}}
    risk = {"risk_tier": "L2", "findings": [], "risk_drivers": [],
            "rationale": "x", "decision": "merge"}
    return gen.create_bundle(pr=_stub_pr(n), analysis=analysis, risk_result=risk,
                             repository="owner/repo", commit_sha=commit,
                             attestation_key=priv_pem)


def _resign(bundle, priv):
    """Forge: re-sign the current bundle bytes with `priv`, embed its pubkey."""
    content = canonical_json_dumps(
        {k: v for k, v in bundle.items() if k != "signatures"}).encode()
    sig = priv.sign(content)
    pub = priv.public_key()
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {
        "signature_id": "forged", "algorithm": "ed25519", "signer_id": "attacker",
        "signature_value": base64.b64encode(sig).decode(),
        "public_key_id": "sha256:" + hashlib.sha256(der).hexdigest(),
        "public_key": pem, "signed_at": "2026-06-24T00:00:00Z",
    }


# --- positive ---------------------------------------------------------------
def test_legit_signed_verifies_against_trusted_fingerprint():
    priv, pem, fp = _gen_key()
    b = _signed_bundle(pem)
    ok, msg = verify_bundle_chain(b, trusted_fingerprints={fp}, require_signature=True)
    assert ok, msg


def test_unsigned_is_integrity_only_ok_without_trust():
    gen = BundleGenerator()
    b = gen.create_bundle(pr=_stub_pr(), analysis={"files_changed": 1, "lines_added": 1,
        "lines_removed": 0, "sensitive_zones": [], "diff_hash": "a", "multi_model_review": {}},
        risk_result={"risk_tier": "L2", "findings": [], "risk_drivers": [], "rationale": "x",
        "decision": "merge"}, repository="o/r", commit_sha="c0ffee")
    ok, _ = verify_bundle_chain(b)               # no trust args -> integrity tier
    assert ok
    ok2, _ = verify_bundle_chain(b, require_signature=True)   # but anti-forgery mode rejects unsigned
    assert not ok2


# --- 7 forge vectors (all must REJECT) --------------------------------------
def test_v1_resign_with_own_key_rejected():
    priv, pem, fp = _gen_key()
    attacker, _, _ = _gen_key()
    b = _signed_bundle(pem)
    b["summary"]["decision"] = "FORGED"
    BundleGenerator()._compute_bundle_hash  # ensure attr exists
    b["bundle_hash"] = BundleGenerator._compute_bundle_hash(b)
    b["signatures"] = [_resign(b, attacker)]     # attacker re-signs + embeds own key
    ok, msg = verify_bundle_chain(b, trusted_fingerprints={fp}, require_signature=True)
    assert not ok, "attacker key not in trusted set must be rejected"


def test_v2_stale_signature_rejected():
    priv, pem, fp = _gen_key()
    b = _signed_bundle(pem)
    b["summary"]["decision"] = "FORGED"          # mutate, keep original signature
    b["bundle_hash"] = BundleGenerator._compute_bundle_hash(b)
    ok, msg = verify_bundle_chain(b, trusted_fingerprints={fp}, require_signature=True)
    assert not ok, "stale signature over old payload must fail"


def test_v3_strip_downgrade_rejected():
    priv, pem, fp = _gen_key()
    b = _signed_bundle(pem)
    b.pop("signatures", None)
    b.pop("bundle_hash", None)
    b.pop("immutability_proof", None)
    b["summary"]["decision"] = "FORGED"
    ok, msg = verify_bundle_chain(b, trusted_fingerprints={fp}, require_signature=True)
    assert not ok, "stripped/downgraded bundle must fail in anti-forgery mode"


def test_v4_hmac_is_not_antiforgery():
    gen = BundleGenerator()
    b = gen.create_bundle(pr=_stub_pr(), analysis={"files_changed": 1, "lines_added": 1,
        "lines_removed": 0, "sensitive_zones": [], "diff_hash": "a", "multi_model_review": {}},
        risk_result={"risk_tier": "L2", "findings": [], "risk_drivers": [], "rationale": "x",
        "decision": "merge"}, repository="o/r", commit_sha="hmac01",
        attestation_key="shared-secret", allow_insecure_signature_fallback=True)
    assert b["signatures"] and b["signatures"][0]["algorithm"] == "hmac-sha256"
    ok, msg = verify_bundle_chain(b, trusted_fingerprints={"sha256:whatever"},
                                  require_signature=True)
    assert not ok, "HMAC signature must not satisfy anti-forgery"


def test_v5_key_id_spoof_rejected():
    priv, pem, fp = _gen_key()
    attacker, _, _ = _gen_key()
    b = _signed_bundle(pem)
    b["summary"]["decision"] = "FORGED"
    b["bundle_hash"] = BundleGenerator._compute_bundle_hash(b)
    forged = _resign(b, attacker)
    forged["public_key_id"] = fp                 # LIE: claim the trusted fingerprint
    b["signatures"] = [forged]
    ok, msg = verify_bundle_chain(b, trusted_fingerprints={fp}, require_signature=True)
    assert not ok, "fingerprint must be recomputed from the embedded key, not trusted from the claim"


def test_v6_canonicalization_is_deterministic():
    a = canonical_json_dumps({"b": 1, "a": 2})
    b = canonical_json_dumps({"a": 2, "b": 1})
    assert a == b


def test_v7_replay_signature_into_other_bundle_rejected():
    priv, pem, fp = _gen_key()
    b1 = _signed_bundle(pem, commit="aaaaaaa", n=7)
    b2 = _signed_bundle(pem, commit="bbbbbbb", n=8)
    b2["signatures"] = b1["signatures"]          # paste b1's signature onto b2
    ok, msg = verify_bundle_chain(b2, trusted_fingerprints={fp}, require_signature=True)
    assert not ok, "a signature from another bundle must not verify here"


def test_strip_both_seal_fields_rejected():
    # downgrade: delete bundle_hash AND immutability_proof, mutate -> still rejected
    # because version/items still mark it modern.
    gen = BundleGenerator()
    b = gen.create_bundle(pr=_stub_pr(), analysis={"files_changed": 1, "lines_added": 1,
        "lines_removed": 0, "sensitive_zones": [], "diff_hash": "a", "multi_model_review": {}},
        risk_result={"risk_tier": "L2", "findings": [], "risk_drivers": [], "rationale": "x",
        "decision": "merge"}, repository="o/r", commit_sha="dg01")
    b["summary"]["decision"] = "FORGED"
    b.pop("bundle_hash", None)
    b.pop("immutability_proof", None)
    ok, msg = verify_bundle_chain(b)             # integrity tier, no trust args
    assert not ok, "modern bundle stripped of its seal must not pass on event chain"


def test_strip_all_markers_but_keep_summary_rejected():
    # Codex re-audit attack: strip bundle_hash + immutability_proof + items +
    # version + guardspine_spec_version, mutate summary -> must still reject,
    # because the forged 'summary' is itself a sealed-class field.
    gen = BundleGenerator()
    b = gen.create_bundle(pr=_stub_pr(), analysis={"files_changed": 1, "lines_added": 1,
        "lines_removed": 0, "sensitive_zones": [], "diff_hash": "a", "multi_model_review": {}},
        risk_result={"risk_tier": "L2", "findings": [], "risk_drivers": [], "rationale": "x",
        "decision": "merge"}, repository="o/r", commit_sha="dg02")
    b["summary"]["decision"] = "FORGED"
    for k in ("bundle_hash", "immutability_proof", "items", "version",
              "guardspine_spec_version"):
        b.pop(k, None)
    ok, msg = verify_bundle_chain(b)
    assert not ok, "keeping a forged summary without bundle_hash must be rejected"


def test_present_but_empty_rich_field_still_requires_seal():
    # Codex round-3: presence, not truthiness. A bundle with an empty rich field and
    # no bundle_hash must still be rejected (no event-only downgrade).
    for field, empty in (("summary", {}), ("analysis_snapshot", {}), ("items", []),
                         ("context", {}), ("immutability_proof", {})):
        b = {"events": [], field: empty}
        # give it a minimal valid event chain so we reach the seal check
        gen = BundleGenerator()
        good = gen.create_bundle(pr=_stub_pr(), analysis={"files_changed": 1, "lines_added": 1,
            "lines_removed": 0, "sensitive_zones": [], "diff_hash": "a", "multi_model_review": {}},
            risk_result={"risk_tier": "L2", "findings": [], "risk_drivers": [], "rationale": "x",
            "decision": "merge"}, repository="o/r", commit_sha="empty1")
        b = {"events": good["events"], "hash_chain": good["hash_chain"], field: empty}
        ok, msg = verify_bundle_chain(b)
        assert not ok, f"present-but-empty {field} with no bundle_hash must be rejected"


def test_trust_anchor_enforces_without_require_flag():
    priv, pem, fp = _gen_key()
    gen = BundleGenerator()
    b = gen.create_bundle(pr=_stub_pr(), analysis={"files_changed": 1, "lines_added": 1,
        "lines_removed": 0, "sensitive_zones": [], "diff_hash": "a", "multi_model_review": {}},
        risk_result={"risk_tier": "L2", "findings": [], "risk_drivers": [], "rationale": "x",
        "decision": "merge"}, repository="o/r", commit_sha="ta01")  # UNSIGNED
    ok, _ = verify_bundle_chain(b, trusted_fingerprints={fp})  # no require flag
    assert not ok, "passing a trust anchor must enforce a valid trusted signature"


def test_reseal_signed_without_key_raises():
    priv, pem, fp = _gen_key()
    b = _signed_bundle(pem)
    try:
        BundleGenerator().seal_bundle(b)         # no key, would drop the signature
        assert False, "must refuse to silently drop a signature"
    except ValueError:
        pass


def test_reseal_with_key_preserves_signature():
    priv, pem, fp = _gen_key()
    b = _signed_bundle(pem)
    b["analysis_snapshot"]["sanitization"] = {"redaction_count": 1}  # post-seal mutation
    BundleGenerator().seal_bundle(b, attestation_key=pem)            # re-sign
    ok, msg = verify_bundle_chain(b, trusted_fingerprints={fp}, require_signature=True)
    assert ok, msg


def test_malformed_signatures_fail_closed_no_crash():
    priv, pem, fp = _gen_key()
    for bad in ("not-a-list", 123, ["not-a-dict", 5], [{}], [{"algorithm": "ed25519"}]):
        b = _signed_bundle(pem)
        b["signatures"] = bad
        b["bundle_hash"] = BundleGenerator._compute_bundle_hash(b)
        ok, _ = verify_bundle_chain(b, trusted_fingerprints={fp}, require_signature=True)
        assert ok is False, f"malformed signatures {bad!r} must fail closed, not pass/crash"


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    bad = 0
    for fn in fns:
        try:
            fn(); print("PASS", fn.__name__)
        except Exception as e:
            bad += 1; print("FAIL", fn.__name__, "->", type(e).__name__, e)
    sys.exit(1 if bad else 0)
