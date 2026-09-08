"""Real-engine preservation and detection gates for the 2.2.2 candidate.

Success requires both exact benign-content preservation and real PII detection.
Published test-card digits are synthetic controls, not production observations.
Residual diff-marker boundary failures remain red; no skips or allowlists.
"""

import re

import pytest

from src.pii_shield import PIIShieldClient


@pytest.mark.parametrize("ending", ["", "\n", "\r\n"])
@pytest.mark.parametrize("marker", ["+", "-", " "])
@pytest.mark.parametrize("value", [
    "total,4532015112.830366",
    "price,378282246310005.00",
    "num,4012888888881881.00",
])
def test_decimal_preserved_exactly(value, marker, ending):
    text = marker + value + ending
    result = PIIShieldClient(enabled=True).sanitize_diff(text)
    assert result.sanitized_text == text
    assert not result.changed
    assert result.redaction_count == 0


@pytest.mark.parametrize("marker", ["+", "-", " "])
@pytest.mark.parametrize("token", ["report.csv", "config.yaml", "src/main.go", "Traceback"])
def test_diff_tokens_preserved_exactly(marker, token):
    text = marker + token + "\n"
    result = PIIShieldClient(enabled=True).sanitize_diff(text)
    assert result.sanitized_text == text
    assert not result.changed


def test_complete_benign_diff_preserved():
    text = ("diff --git a/report.csv b/report.csv\n"
            "index 1234567..7654321 100644\n"
            "--- a/report.csv\n+++ b/report.csv\n@@ -1 +1 @@\n"
            "-total,4532015112.830366\n+total,4012888888881881.00\n")
    result = PIIShieldClient(enabled=True).sanitize_diff(text)
    assert result.sanitized_text == text
    assert not result.changed


@pytest.mark.parametrize("secret", ["4111111111111111", "378282246310005", "alice@example.com"])
@pytest.mark.parametrize("marker", ["", "+", "-"])
def test_real_pii_still_detected(secret, marker):
    text = marker + secret + "\n"
    result = PIIShieldClient(enabled=True).sanitize_diff(text)
    assert result.changed
    assert secret not in result.sanitized_text
    assert "[HIDDEN" in result.sanitized_text
    assert result.redaction_count > 0


@pytest.mark.parametrize("suffix", [
    " then unrelated text: order #4471, ship to Denver, total 82.50\n",
    ' said "hello there and more text after\n',
])
def test_only_email_span_changes(suffix):
    prefix = "+contact "
    result = PIIShieldClient(enabled=True).sanitize_text(prefix + "alice@example.com" + suffix)
    assert result.changed
    assert "alice@example.com" not in result.sanitized_text
    assert re.fullmatch(re.escape(prefix) + r"\[HIDDEN[^\]\r\n]*\]" + re.escape(suffix),
                        result.sanitized_text)


def test_json_sibling_preserves_shape_and_detects_pii():
    document = {"email": "alice@example.com", "total": "4532015112.830366"}
    sanitized, result = PIIShieldClient(enabled=True).sanitize_json_document(document)
    assert set(sanitized) == set(document)
    assert sanitized["total"] == document["total"]
    assert "alice@example.com" not in sanitized["email"]
    assert "[HIDDEN" in sanitized["email"]
    assert result.changed


def test_engine_fatal_marker_is_not_sanitized_success(monkeypatch):
    client = PIIShieldClient(enabled=True, fail_closed=True)
    monkeypatch.setattr(client, "_redact", lambda text: "[PII_SHIELD_DROP: FATAL_ERROR]")
    from src.pii_shield import PIIShieldError
    with pytest.raises(PIIShieldError):
        client.sanitize_diff("+alice@example.com\n")
