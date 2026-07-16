"""Fail-first proof for scripts/g_code_e2e_verify.py -- the read-back +
verify assertion that closes the G-CODE-E2E loop (action writes a bundle ->
this reads it back by the SAME id and asserts it is provably verified).

Each failure mode below must make the gate RED (VerifyFailure / exit 1);
only an exact verified bundle, matched by bundle_id, passes.

Hermetic: no network (urllib.request.urlopen is monkeypatched).
"""
import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import g_code_e2e_verify as verify_mod  # noqa: E402


API_URL = "https://api.guardspine.ai/api/v1"
BUNDLE_ID = "b-abc123"


class _Resp:
    """Minimal stand-in for the object urllib.request.urlopen() returns."""

    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    def read(self):
        return self._body

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _good_body(**overrides) -> dict:
    body = {
        "bundle_id": BUNDLE_ID,
        "raw_sha256": "deadbeef" * 8,
        "imported_at": "2026-07-16T00:00:00Z",
        "verified": True,
        "version": "0.2.0",
        "item_count": 3,
        "root_hash": "sha256:" + ("ab" * 32),  # 64 hex chars
    }
    body.update(overrides)
    return body


def _mock_urlopen(monkeypatch, body: dict):
    # The script fetches via the origin-safe opener (which strips Authorization
    # on a cross-origin redirect), not the bare urllib.request.urlopen, so the
    # mock patches the opener's .open method.
    monkeypatch.setattr(
        verify_mod._ORIGIN_SAFE_OPENER,
        "open",
        lambda *a, **k: _Resp(json.dumps(body).encode("utf-8")),
    )


# --- verify() / assert_verified_bundle(): the assertion logic itself ---


def test_verified_true_with_good_fields_passes(monkeypatch):
    _mock_urlopen(monkeypatch, _good_body())
    fields = verify_mod.verify(API_URL, "key", BUNDLE_ID)
    assert fields["bundle_id"] == BUNDLE_ID
    assert fields["verified"] is True
    assert fields["root_hash"] == "sha256:" + ("ab" * 32)
    assert fields["item_count"] == 3


def test_verified_false_fails(monkeypatch):
    _mock_urlopen(monkeypatch, _good_body(verified=False))
    with pytest.raises(verify_mod.VerifyFailure, match="not verified"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_verified_truthy_non_true_fails(monkeypatch):
    """STRICT identity check: verified=1 or "true" is not verified=True."""
    _mock_urlopen(monkeypatch, _good_body(verified=1))
    with pytest.raises(verify_mod.VerifyFailure, match="not verified"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_http_404_fails(monkeypatch):
    def _raise(*a, **k):
        raise urllib.error.HTTPError(
            url=API_URL + f"/bundles/import/{BUNDLE_ID}",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=io.BytesIO(b'{"detail":"Imported bundle not found"}'),
        )

    monkeypatch.setattr(verify_mod._ORIGIN_SAFE_OPENER, "open", _raise)
    with pytest.raises(verify_mod.VerifyFailure, match="HTTP 404"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_unreachable_host_fails(monkeypatch):
    def _raise(*a, **k):
        raise urllib.error.URLError("Cloudflare 1010: access denied")

    monkeypatch.setattr(verify_mod._ORIGIN_SAFE_OPENER, "open", _raise)
    with pytest.raises(verify_mod.VerifyFailure, match="unreachable"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_missing_root_hash_fails(monkeypatch):
    _mock_urlopen(monkeypatch, _good_body(root_hash=None))
    with pytest.raises(verify_mod.VerifyFailure, match="root_hash"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_empty_root_hash_fails(monkeypatch):
    _mock_urlopen(monkeypatch, _good_body(root_hash=""))
    with pytest.raises(verify_mod.VerifyFailure, match="root_hash"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_non_string_truthy_root_hash_fails(monkeypatch):
    """LOW-6 hardening: root_hash must be a non-empty STRING, not just any
    truthy value (e.g. an int, bool, or list would previously pass the bare
    `if not root_hash` check)."""
    _mock_urlopen(monkeypatch, _good_body(root_hash=12345))
    with pytest.raises(verify_mod.VerifyFailure, match="root_hash"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_root_hash_missing_sha256_prefix_fails(monkeypatch):
    _mock_urlopen(monkeypatch, _good_body(root_hash="ab" * 32))  # no "sha256:" prefix
    with pytest.raises(verify_mod.VerifyFailure, match="root_hash"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_root_hash_wrong_length_fails(monkeypatch):
    _mock_urlopen(monkeypatch, _good_body(root_hash="sha256:abc123"))  # too short
    with pytest.raises(verify_mod.VerifyFailure, match="root_hash"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_root_hash_non_hex_fails(monkeypatch):
    """Right length + prefix but not hex ('sha256:' + 64 'z') must fail."""
    _mock_urlopen(monkeypatch, _good_body(root_hash="sha256:" + ("z" * 64)))
    with pytest.raises(verify_mod.VerifyFailure, match="root_hash"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_zero_item_count_fails(monkeypatch):
    _mock_urlopen(monkeypatch, _good_body(item_count=0))
    with pytest.raises(verify_mod.VerifyFailure, match="item_count"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_bundle_id_mismatch_fails(monkeypatch):
    """The ID-traceable assertion: a read-back that returns a DIFFERENT
    bundle than the one the action emitted must never pass, even if that
    other bundle is itself verified."""
    _mock_urlopen(monkeypatch, _good_body(bundle_id="some-other-bundle"))
    with pytest.raises(verify_mod.VerifyFailure, match="mismatch"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


def test_non_dict_body_fails(monkeypatch):
    monkeypatch.setattr(
        verify_mod._ORIGIN_SAFE_OPENER,
        "open",
        lambda *a, **k: _Resp(json.dumps([1, 2, 3]).encode("utf-8")),
    )
    with pytest.raises(verify_mod.VerifyFailure, match="non-object"):
        verify_mod.verify(API_URL, "key", BUNDLE_ID)


# --- main(): CLI wiring and exit codes ---


def test_main_exits_zero_on_success(monkeypatch):
    monkeypatch.setenv("GUARDSPINE_API_KEY", "key")
    _mock_urlopen(monkeypatch, _good_body())
    assert verify_mod.main([API_URL, BUNDLE_ID]) == 0


def test_main_exits_one_and_prints_error_on_failure(monkeypatch, capsys):
    monkeypatch.setenv("GUARDSPINE_API_KEY", "key")
    _mock_urlopen(monkeypatch, _good_body(verified=False))
    rc = verify_mod.main([API_URL, BUNDLE_ID])
    assert rc == 1
    captured = capsys.readouterr()
    assert "::error::" in captured.out


def test_main_exits_one_on_404(monkeypatch, capsys):
    monkeypatch.setenv("GUARDSPINE_API_KEY", "key")

    def _raise(*a, **k):
        raise urllib.error.HTTPError(
            url=API_URL, code=404, msg="Not Found", hdrs=None, fp=io.BytesIO(b"{}")
        )

    monkeypatch.setattr(verify_mod._ORIGIN_SAFE_OPENER, "open", _raise)
    rc = verify_mod.main([API_URL, BUNDLE_ID])
    assert rc == 1
    assert "::error::" in capsys.readouterr().out


def test_main_fails_closed_on_missing_api_key(monkeypatch):
    monkeypatch.delenv("GUARDSPINE_API_KEY", raising=False)
    assert verify_mod.main([API_URL, BUNDLE_ID]) == 1


def test_main_fails_closed_on_empty_bundle_id(monkeypatch):
    monkeypatch.setenv("GUARDSPINE_API_KEY", "key")
    assert verify_mod.main([API_URL, ""]) == 1


def test_main_requires_exactly_two_args():
    assert verify_mod.main([API_URL]) == 1
    assert verify_mod.main([]) == 1
