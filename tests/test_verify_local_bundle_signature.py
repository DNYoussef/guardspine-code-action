"""Fail-first proof for scripts/verify_local_bundle_signature.py -- the
independent (non-backend) hash-chain + signature verification of a locally
saved bundle (MEDIUM-5 fold-in).

Hermetic: no network. Builds real bundles with a real ed25519 key via
BundleGenerator (the same code path the action uses), writes them to a temp
file, and drives the script's own functions + main() against them.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from src.bundle_generator import BundleGenerator

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import verify_local_bundle_signature as verify_mod  # noqa: E402


def _gen_key_pem():
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return priv_pem


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
KEY_ID = "codeguard-ci"


def _signed_bundle(priv_pem, key_id=KEY_ID):
    gen = BundleGenerator()
    return gen.create_bundle(
        pr=_stub_pr(), analysis=_ANALYSIS, risk_result=_RISK,
        repository="owner/repo", commit_sha="deadbeef",
        attestation_key=priv_pem, attestation_key_id=key_id,
    )


def _write_bundle(tmp_path, bundle) -> str:
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    return str(p)


def test_valid_signed_bundle_passes(tmp_path):
    priv_pem = _gen_key_pem()
    bundle = _signed_bundle(priv_pem)
    bundle_path = _write_bundle(tmp_path, bundle)

    message = verify_mod.verify_local_bundle(bundle_path, KEY_ID, priv_pem)
    assert "verified" in message.lower()


def test_main_exits_zero_on_success(tmp_path, monkeypatch):
    priv_pem = _gen_key_pem()
    bundle = _signed_bundle(priv_pem)
    bundle_path = _write_bundle(tmp_path, bundle)

    monkeypatch.setenv("GUARDSPINE_ATTESTATION_KEY", priv_pem)
    assert verify_mod.main([bundle_path, KEY_ID]) == 0


def test_tampered_bundle_fails(tmp_path):
    """A bundle mutated after signing must fail -- this is the hash-chain /
    bundle_hash recompute doing its job."""
    priv_pem = _gen_key_pem()
    bundle = _signed_bundle(priv_pem)
    bundle["summary"]["risk_tier"] = "L0"  # tamper after sealing
    bundle_path = _write_bundle(tmp_path, bundle)

    with pytest.raises(verify_mod.LocalVerifyFailure):
        verify_mod.verify_local_bundle(bundle_path, KEY_ID, priv_pem)


def test_wrong_key_id_fails(tmp_path):
    """trusted_keys is keyed by key_id -- a mismatched key_id must not
    accidentally still verify against some other trusted entry."""
    priv_pem = _gen_key_pem()
    bundle = _signed_bundle(priv_pem, key_id=KEY_ID)
    bundle_path = _write_bundle(tmp_path, bundle)

    with pytest.raises(verify_mod.LocalVerifyFailure):
        verify_mod.verify_local_bundle(bundle_path, "some-other-key-id", priv_pem)


def test_wrong_private_key_fails(tmp_path):
    """Deriving the public key from a DIFFERENT private key than the one that
    actually signed must not verify (proves this isn't a tautology)."""
    priv_pem = _gen_key_pem()
    other_priv_pem = _gen_key_pem()
    bundle = _signed_bundle(priv_pem)
    bundle_path = _write_bundle(tmp_path, bundle)

    with pytest.raises(verify_mod.LocalVerifyFailure):
        verify_mod.verify_local_bundle(bundle_path, KEY_ID, other_priv_pem)


def test_unsigned_bundle_fails(tmp_path):
    """require_signature=True must reject an unsigned bundle even though its
    hash chain is otherwise intact."""
    gen = BundleGenerator()
    bundle = gen.create_bundle(
        pr=_stub_pr(), analysis=_ANALYSIS, risk_result=_RISK,
        repository="owner/repo", commit_sha="deadbeef",
    )
    priv_pem = _gen_key_pem()
    bundle_path = _write_bundle(tmp_path, bundle)
    with pytest.raises(verify_mod.LocalVerifyFailure):
        verify_mod.verify_local_bundle(bundle_path, KEY_ID, priv_pem)


def test_missing_bundle_file_fails():
    priv_pem = _gen_key_pem()
    with pytest.raises(verify_mod.LocalVerifyFailure, match="not found"):
        verify_mod.verify_local_bundle("/no/such/bundle.json", KEY_ID, priv_pem)


def test_garbage_private_key_fails(tmp_path):
    priv_pem = _gen_key_pem()
    bundle = _signed_bundle(priv_pem)
    bundle_path = _write_bundle(tmp_path, bundle)

    with pytest.raises(verify_mod.LocalVerifyFailure):
        verify_mod.verify_local_bundle(bundle_path, KEY_ID, "not a pem key")


def test_main_fails_closed_on_missing_secret(tmp_path, monkeypatch):
    priv_pem = _gen_key_pem()
    bundle = _signed_bundle(priv_pem)
    bundle_path = _write_bundle(tmp_path, bundle)

    monkeypatch.delenv("GUARDSPINE_ATTESTATION_KEY", raising=False)
    assert verify_mod.main([bundle_path, KEY_ID]) == 1


def test_main_exits_one_and_prints_error_on_tamper(tmp_path, monkeypatch, capsys):
    priv_pem = _gen_key_pem()
    bundle = _signed_bundle(priv_pem)
    bundle["summary"]["risk_tier"] = "L0"
    bundle_path = _write_bundle(tmp_path, bundle)

    monkeypatch.setenv("GUARDSPINE_ATTESTATION_KEY", priv_pem)
    rc = verify_mod.main([bundle_path, KEY_ID])
    assert rc == 1
    assert "::error::" in capsys.readouterr().out
