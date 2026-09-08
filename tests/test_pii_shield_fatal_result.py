"""An engine failure is not sanitized content, across every public caller."""
import pytest

from src.pii_shield import PIIShieldClient, PIIShieldError


FATAL = "[PII_SHIELD_DROP: FATAL_ERROR]"


def test_exact_whole_input_sentinel_collision_fails_closed(monkeypatch):
    client = PIIShieldClient(enabled=True)
    monkeypatch.setattr(client, "_redact", lambda text: text)
    with pytest.raises(PIIShieldError, match="engine returned a fatal error"):
        client.sanitize_text(FATAL)


@pytest.mark.parametrize("method,payload", [
    ("sanitize_text", "alice@example.com"),
    ("sanitize_diff", "+alice@example.com\n"),
    ("sanitize_json_document", {"email": "alice@example.com"}),
])
@pytest.mark.parametrize("mode,fail_closed", [("auto", True), ("remote", False)])
def test_fatal_result_raises(method, payload, mode, fail_closed, monkeypatch):
    client = PIIShieldClient(enabled=True, mode=mode, fail_closed=fail_closed)
    monkeypatch.setattr(client, "_redact", lambda text: FATAL)
    with pytest.raises(PIIShieldError, match="engine returned a fatal error"):
        getattr(client, method)(payload)


@pytest.mark.parametrize("method,payload", [
    ("sanitize_text", "alice@example.com"),
    ("sanitize_diff", "+alice@example.com\n"),
    ("sanitize_json_document", {"email": "alice@example.com", "root_hash": "abc123"}),
])
def test_explicit_fail_open_is_reported_not_sanitized_success(method, payload, monkeypatch):
    client = PIIShieldClient(enabled=True, fail_closed=False)
    monkeypatch.setattr(client, "_redact", lambda text: FATAL)
    returned = getattr(client, method)(payload)
    if method == "sanitize_json_document":
        document, result = returned
        assert document == payload
    else:
        result = returned
        assert result.sanitized_text == payload
    assert result.provider == "passthrough"
    assert not result.changed
    assert "fail-open" in result.metadata["warning"]
    assert "alice@example.com" not in result.metadata["engine_error"]


def test_changed_content_can_contain_fatal_literal(monkeypatch):
    client = PIIShieldClient(enabled=True)
    output = FATAL + " documents a failure; [HIDDEN:123456]\n"
    monkeypatch.setattr(client, "_redact", lambda text: output)
    result = client.sanitize_text(FATAL + " documents a failure; alice@example.com\n")
    assert result.sanitized_text == output
    assert result.changed


def test_json_can_contain_fatal_literal(monkeypatch):
    client = PIIShieldClient(enabled=True)
    monkeypatch.setattr(client, "_redact", lambda text: text)
    payload = {"example": FATAL}
    document, result = client.sanitize_json_document(payload)
    assert document == payload
    assert not result.changed


@pytest.mark.parametrize("method,payload", [
    ("sanitize_text", "alice@example.com"),
    ("sanitize_diff", "+alice@example.com\n"),
    ("sanitize_json_document", {"email": "alice@example.com"}),
])
@pytest.mark.parametrize("mode,fail_closed", [("auto", True), ("auto", False), ("remote", False)])
def test_actual_package_allocation_failure_is_observable(method, payload, mode, fail_closed, monkeypatch):
    from src import pii_shield as adapter

    shield_type, config_type = adapter._load_wasm_engine()
    policies = []

    def failing_shield(config):
        policies.append(config.fail_policy)
        shield = shield_type(config)
        monkeypatch.setattr(shield, "allocate", lambda store, size: 0)
        return shield

    monkeypatch.setattr(adapter, "_load_wasm_engine", lambda: (failing_shield, config_type))
    client = PIIShieldClient(enabled=True, mode=mode, fail_closed=fail_closed)
    if mode == "remote" or fail_closed:
        with pytest.raises(PIIShieldError, match="engine returned a fatal error"):
            getattr(client, method)(payload)
    else:
        returned = getattr(client, method)(payload)
        if method == "sanitize_json_document":
            document, result = returned
            assert document == payload
        else:
            result = returned
            assert result.sanitized_text == payload
        assert result.provider == "passthrough"
        assert "fail-open" in result.metadata["warning"]
    assert policies == ["closed"]


@pytest.mark.parametrize("text", [
    "example " + FATAL + " remains text\n",
    FATAL + " is a documented return value\n",
    "+" + FATAL + "\n",
])
def test_embedded_fatal_literal_is_not_an_engine_failure(text, monkeypatch):
    client = PIIShieldClient(enabled=True)
    monkeypatch.setattr(client, "_redact", lambda value: value)
    result = client.sanitize_text(text)
    assert result.sanitized_text == text
    assert not result.changed
