"""Failure reports cannot contain engine text or attest redaction that failed."""
import copy
import json
import traceback

import pytest

from src.pii_shield import PIIShieldClient, PIIShieldError


SECRET = "PRIVATE_EXCEPTION_CANARY_4f8c"
CALLS = [
    ("sanitize_text", "contact alice@example.com"),
    ("sanitize_diff", "+contact alice@example.com\n"),
    ("sanitize_json_document", {"message": "alice@example.com", "root_hash": "abc123"}),
]


def assert_passthrough(result, error_key, label):
    assert result.provider == "passthrough"
    assert result.changed is False
    assert result.redaction_count == 0
    assert result.redactions_by_type == {}
    assert result.signals == []
    assert result.to_sensitive_zones() == []
    assert result.to_metadata()["signal_count"] == 0
    assert result.to_metadata()["enabled"] is True
    assert result.input_hash == result.output_hash
    assert result.output_hash == PIIShieldClient._sha256(result.sanitized_text)
    assert result.metadata[error_key] == label
    assert "fail-open" in result.metadata["warning"]
    assert SECRET not in json.dumps(result.to_metadata())


@pytest.mark.parametrize("method,payload", CALLS)
@pytest.mark.parametrize("mode,closed", [("auto", True), ("remote", True), ("remote", False), ("auto", False)])
def test_engine_exception_is_private(method, payload, mode, closed, monkeypatch):
    client = PIIShieldClient(enabled=True, mode=mode, fail_closed=closed)

    def fail(text):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(client, "_redact", fail)
    if mode == "remote" or closed:
        with pytest.raises(PIIShieldError) as caught:
            getattr(client, method)(payload)
        rendered = "".join(traceback.format_exception(caught.value))
        assert SECRET not in rendered
        assert SECRET not in repr(caught.value.args)
        assert str(caught.value) == "PII-Shield engine failed"
    else:
        returned = getattr(client, method)(payload)
        if method == "sanitize_json_document":
            document, result = returned
            assert document == payload
        else:
            result = returned
            assert result.sanitized_text == payload
        assert_passthrough(result, "engine_error", "engine_failure")


@pytest.mark.parametrize("mode,closed", [("auto", True), ("remote", True), ("remote", False), ("auto", False)])
def test_invalid_json_obeys_policy_and_reports_original(mode, closed, monkeypatch):
    client = PIIShieldClient(enabled=True, mode=mode, fail_closed=closed)
    monkeypatch.setattr(client, "_redact", lambda text: "not JSON [HIDDEN:123]")
    payload = {"root_hash": "abc123", "message": "alice@example.com",
               "nested": {"inner_hash": "def456", "value": "unchanged"}}
    before = copy.deepcopy(payload)
    if mode == "remote" or closed:
        with pytest.raises(PIIShieldError) as caught:
            client.sanitize_json_document(payload, purpose=SECRET)
        assert SECRET not in "".join(traceback.format_exception(caught.value))
        assert str(caught.value) == "PII-Shield returned invalid JSON"
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__ is True
    else:
        document, result = client.sanitize_json_document(payload, purpose=SECRET)
        assert document == before
        assert list(document) == list(before)
        assert list(document["nested"]) == list(before["nested"])
        # Result hashes/text describe engine input, which excludes preserved hashes.
        assert json.loads(result.sanitized_text) == {
            "message": "alice@example.com", "nested": {"value": "unchanged"}}
        assert_passthrough(result, "parse_error", "invalid_json")
    assert payload == before


@pytest.mark.parametrize("method,payload", CALLS)
def test_disabled_metadata_and_successful_redaction_are_distinct(method, payload, monkeypatch):
    disabled = PIIShieldClient(enabled=False)

    def unexpected(text):
        pytest.fail("disabled shield called engine")

    monkeypatch.setattr(disabled, "_redact", unexpected)
    returned = getattr(disabled, method)(payload)
    if method == "sanitize_json_document":
        document, result = returned
        assert document == payload
    else:
        result = returned
        assert result.sanitized_text == payload
    assert result.to_metadata()["enabled"] is False
    assert result.provider == "none"
    assert result.input_hash == result.output_hash

    active = PIIShieldClient(enabled=True)
    monkeypatch.setattr(active, "_redact", lambda text: "[HIDDEN:123]")
    result = active.sanitize_text("alice@example.com")
    assert result.to_metadata()["enabled"] is True
    assert result.provider == "pii-shield-wasi"
    assert result.changed is True
    assert result.redaction_count == 1
    assert result.signals
    assert result.output_hash == active._sha256("[HIDDEN:123]")


def test_privacy_oracle_detects_known_bad_exception():
    try:
        raise RuntimeError(SECRET)
    except RuntimeError as error:
        assert SECRET in "".join(traceback.format_exception(error))


def test_engine_failure_preserves_json_key_order(monkeypatch):
    client = PIIShieldClient(enabled=True, fail_closed=False)

    def fail(text):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(client, "_redact", fail)
    original = {"root_hash": "abc123", "message": "alice@example.com"}
    document, result = client.sanitize_json_document(original)
    assert list(document) == list(original)
    assert_passthrough(result, "engine_error", "engine_failure")
