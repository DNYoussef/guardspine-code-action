"""Fail-first proof for two R0.6 fold-in fixes to BundleGenerator:

CRITICAL-2 (bundle_id uniqueness): a workflow_dispatch run has no real PR, so
repository/pr_number/commit_sha are constant across runs -- the OLD
_generate_bundle_id derives bundle_id purely from those three fields, so
every such run mints the IDENTICAL bundle_id and a backend that rejects
duplicate imports (409 DuplicateBundleError) refuses every run after the
first. id_nonce must make two runs' bundle_ids differ, while an empty/absent
nonce must reproduce the original (pre-fix) deterministic id exactly --
existing callers that never pass id_nonce must see byte-identical output.

CRITICAL-1 (public_key_id must match what the verifier trusts): the
GuardSpine backend's signing_service.verify_signature() looks up
signature["public_key_id"] verbatim in a server-side trusted-key dict -- it
never recomputes or trusts an embedded key. The default public_key_id (a
fingerprint of the DER-encoded key) is useless unless a verifier
independently reproduces that exact fingerprint as a key_id string.
attestation_key_id lets the caller pin public_key_id to whatever key_id
string the verifier actually has configured.

Run: python -m pytest tests/test_bundle_id_nonce_and_key_id.py -q
"""
import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from src.bundle_generator import BundleGenerator


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


def _stub_pr(n=1):
    return SimpleNamespace(
        number=n, title="t", created_at=datetime(2026, 7, 16, tzinfo=timezone.utc),
        user=SimpleNamespace(login="u"), base=SimpleNamespace(ref="main"),
        head=SimpleNamespace(ref="f"),
    )


_ANALYSIS = {
    "files_changed": 1, "lines_added": 1, "lines_removed": 0,
    "sensitive_zones": [], "diff_hash": "abc", "multi_model_review": {},
}
_RISK = {
    "risk_tier": "L2", "findings": [], "risk_drivers": [],
    "rationale": "x", "decision": "merge",
}


def _make_bundle(**kwargs):
    gen = BundleGenerator()
    return gen.create_bundle(
        pr=_stub_pr(), analysis=_ANALYSIS, risk_result=_RISK,
        repository="owner/repo", commit_sha="deadbeef", **kwargs,
    )


# --- CRITICAL-2: bundle_id nonce -------------------------------------------


def test_no_nonce_is_deterministic_and_unchanged_from_original_behavior():
    """Backward compatibility: existing callers that never pass id_nonce must
    keep getting the exact original deterministic id (a pure function of
    repository/pr_number/commit_sha)."""
    b1 = _make_bundle()
    b2 = _make_bundle()
    assert b1["bundle_id"] == b2["bundle_id"]

    import uuid
    expected = str(uuid.uuid5(uuid.NAMESPACE_URL, "owner/repo/pull/1/deadbeef"))
    assert b1["bundle_id"] == expected


def test_same_nonce_yields_same_id():
    b1 = _make_bundle(id_nonce="run-42-1")
    b2 = _make_bundle(id_nonce="run-42-1")
    assert b1["bundle_id"] == b2["bundle_id"]


def test_different_nonce_yields_different_id():
    b1 = _make_bundle(id_nonce="run-42-1")
    b2 = _make_bundle(id_nonce="run-43-1")
    assert b1["bundle_id"] != b2["bundle_id"]


def test_nonce_changes_id_relative_to_no_nonce():
    """A nonce must actually perturb the id -- not silently be a no-op."""
    b_bare = _make_bundle()
    b_nonced = _make_bundle(id_nonce="run-42-1")
    assert b_bare["bundle_id"] != b_nonced["bundle_id"]


def test_nonce_does_not_change_commit_sha_or_context():
    """Only the id seed gets the nonce -- context.commit_sha and the PR event
    data must stay the real, unmodified values."""
    b = _make_bundle(id_nonce="run-42-1")
    assert b["context"]["commit_sha"] == "deadbeef"
    assert b["context"]["repository"] == "owner/repo"
    assert b["context"]["pr_number"] == 1
    assert b["events"][0]["data"]["head_sha"] == "deadbeef"


def test_two_consecutive_runs_same_pr_context_different_run_id_dont_collide():
    """Simulates two workflow_dispatch runs: identical repo/pr_number/commit_sha
    (both always resolve to the synthetic PR 1 + the same default-branch SHA),
    distinguished only by a run-scoped nonce (e.g. github.run_id-run_attempt)."""
    run1 = _make_bundle(id_nonce="1234567890-1")
    run2 = _make_bundle(id_nonce="1234567891-1")
    assert run1["bundle_id"] != run2["bundle_id"]
    # A retried attempt of the SAME run, though, is expected to reuse the id
    # (same run_id-run_attempt seed) -- that's intentional idempotency, not
    # a collision bug.
    retry_same_attempt = _make_bundle(id_nonce="1234567890-1")
    assert run1["bundle_id"] == retry_same_attempt["bundle_id"]


# --- CRITICAL-1: attestation_key_id override --------------------------------


def test_default_public_key_id_is_der_fingerprint_unchanged():
    """Backward compatibility: callers that never pass attestation_key_id must
    keep getting the original sha256(DER SPKI) fingerprint."""
    _, pem, fingerprint = _gen_key()
    b = _make_bundle(attestation_key=pem)
    assert b["signatures"][0]["public_key_id"] == fingerprint


def test_attestation_key_id_override_is_used_verbatim():
    """The verifier (GuardSpine backend) looks up public_key_id as a literal
    string in its own trusted-key map -- it must be exactly what the caller
    configured there, not a derived fingerprint the caller has to reproduce."""
    _, pem, fingerprint = _gen_key()
    b = _make_bundle(attestation_key=pem, attestation_key_id="codeguard-ci")
    sig = b["signatures"][0]
    assert sig["public_key_id"] == "codeguard-ci"
    assert sig["public_key_id"] != fingerprint


def test_reseal_preserves_the_same_attestation_key_id():
    """seal_bundle (used to re-sign after post-hoc mutation, e.g. PII
    sanitization) must carry attestation_key_id through -- otherwise a
    re-signed bundle silently reverts to the fingerprint id and stops
    matching what the verifier has configured."""
    _, pem, _ = _gen_key()
    b = _make_bundle(attestation_key=pem, attestation_key_id="codeguard-ci")
    gen = BundleGenerator()
    gen.seal_bundle(b, attestation_key=pem, attestation_key_id="codeguard-ci")
    assert b["signatures"][0]["public_key_id"] == "codeguard-ci"


def test_signature_still_cryptographically_valid_with_overridden_key_id():
    """The override must only change the label, not break the signature
    itself -- verify_bundle_chain (keyed by the SAME overridden id) must
    still accept it."""
    from src.bundle_generator import verify_bundle_chain

    _, pem, _ = _gen_key()
    priv = serialization.load_pem_private_key(pem.encode(), password=None)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    b = _make_bundle(attestation_key=pem, attestation_key_id="codeguard-ci")
    ok, msg = verify_bundle_chain(
        b, trusted_keys={"codeguard-ci": pub_pem}, require_signature=True,
    )
    assert ok, msg
