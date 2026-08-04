"""Gate: PII-Shield runs in-process via WASM, and there is no HTTP client.

WHAT WAS PROMISED, and to whom. This was committed in writing to Ilya
Ploskovitov, who maintains PII-Shield, on 2026-08-04: move to the published
`pii-shield-wasi` package AND **delete the HTTP client so WASM is the only
path**. The pip bump is the easy half. Deleting the client is the part that
matters, and doing only the bump would satisfy the requirements line while
breaking the actual promise.

WHY IT IS THE PART THAT MATTERS. Three rounds of automated security
hardening went into defending the HTTP path -- SSRF validation, cloud-metadata
blocking, DNS-rebind pinning at connect time. All of that defends a network
hop that does not need to exist. **A request that is never made has no SSRF
surface, no rebinding surface, and no key to leak in a header.** Removing the
path removes the whole class, which is strictly better than hardening it
further.

HOW IT WAS REACHABLE AT ALL, because this is the uncomfortable part. The old
`_sanitize_remote` dispatched on `self.endpoint.lower().startswith("http")`:
HTTP if the endpoint looked like a URL, WASM otherwise. Since `action.yml`
documents that field as "Optional PII-Shield HTTP endpoint", the in-process
path was reachable only by putting a NON-http value into a field documented
as http. Nobody was ever going to do that by accident. Worse, sanitization
ran only `if self.mode in {"auto","remote"} and self.endpoint` -- so with no
endpoint set, and `pii_shield_enabled` defaulting to false, **PII-Shield was
not running in real CodeGuard runs at all.**

So this change does three things, and the tests below pin each:
  1. There is no HTTP client, and no HTTP-defence machinery that only existed
     to protect it.
  2. WASM is the only path, via the published package rather than a vendored
     binary and a hand-rolled wasmtime adapter -- so upstream fixes arrive by
     version bump instead of by copying a 4 MB blob.
  3. Sanitization no longer requires an endpoint to happen. That is what
     turns PII-Shield from configured-but-never-running into actually
     running.

A NOTE ON WHAT IS LOST, stated rather than discovered later. The HTTP API
returned structured findings and metadata; the WASM package exposes
`redact(str) -> str`. Nothing consumed those richer fields -- `sensitive_zones`
in analyzer.py is built from its own analysis, not from the shield's response
-- so the loss is real but not load-bearing. If structured findings are needed
later they come from upstream, not from re-adding a network call.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
PII_SHIELD = SRC / "pii_shield.py"


def _source() -> str:
    return PII_SHIELD.read_text(encoding="utf-8")


def _code_only() -> str:
    """Source with docstrings and comments stripped.

    The first version of these tests scanned raw text and failed on the
    module's OWN docstring, which explains what was deleted and therefore
    names it. A gate that cannot tell code from prose about code will
    either block honest documentation or, worse, be "fixed" by deleting
    the explanation. So: parse, drop docstrings, drop comments, and match
    on what actually executes.
    """
    tree = ast.parse(_source())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body.pop(0)
    return ast.unparse(tree)


# ------------------------------------------------------- 1. the client is gone

def test_no_http_library_is_imported():
    """`requests` and `urllib3` existed in this module ONLY to make and pin
    the outbound call. If either comes back, so has the network hop."""
    tree = ast.parse(_source())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for banned in ("requests", "urllib3", "httpx", "aiohttp"):
        assert banned not in imported, (
            "{} is imported again -- the HTTP client is back".format(banned)
        )


def test_the_http_send_function_is_gone():
    """The function that actually made the call."""
    tree = ast.parse(_source())
    names = {n.name for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "_sanitize_via_http" not in names, "the HTTP sender still exists"


def test_the_ssrf_machinery_is_gone_because_its_reason_is_gone():
    """SSRF validation, metadata blocking and connect-time DNS pinning were
    defences for the outbound request. Keeping them after removing the
    request leaves dead security code, which is worse than none: it implies
    a threat model that no longer applies and invites someone to re-add the
    call it was protecting.
    """
    tree = ast.parse(_source())
    names = {n.name for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for gone in ("_validate_endpoint", "_resolve_endpoint_target",
                 "_pin_endpoint_connection", "_validate_resolved_ip",
                 "_private_endpoint_override_enabled"):
        assert gone not in names, (
            "{} survives -- it only existed to defend the deleted HTTP "
            "call".format(gone)
        )


def test_no_outbound_url_scheme_dispatch_remains():
    """The specific line that made HTTP the default and WASM the
    hard-to-reach fallback."""
    src = _code_only()
    assert "startswith(\"http\")" not in src and "startswith('http')" not in src, (
        "the scheme dispatch is back; WASM is no longer the only path"
    )


# ------------------------------------------- 2. WASM via the published package

def test_the_published_package_is_used_not_a_vendored_binary():
    """Upstream fixes should arrive by version bump, not by copying a 4 MB
    blob into the repo. Ilya shipped four fixes in 2.1.1, two of which land
    directly on cell-level redaction."""
    src = _code_only()
    assert "pii_shield" in src, "the package is not imported"
    assert "wasmtime" not in src, (
        "this module drives wasmtime directly again instead of using the "
        "published package"
    )


def test_the_package_is_pinned_at_the_agreed_version():
    """2.1.1 is what was committed to. A floating pin would mean the promise
    holds only until the next resolve."""
    req = (Path(__file__).resolve().parents[1] / "requirements.txt")
    text = req.read_text(encoding="utf-8")
    match = re.search(r"^pii-shield-wasi==([0-9][0-9.]*)", text, re.MULTILINE)
    assert match, "pii-shield-wasi is not pinned in requirements.txt"
    assert match.group(1) == "2.1.1", (
        "pinned at {} -- the commitment was 2.1.1".format(match.group(1))
    )


def test_redaction_actually_runs_in_process():
    """End to end through the real engine, not a mock. If the WASM path
    cannot redact, deleting the HTTP path removed the only thing that
    worked."""
    pytest.importorskip("pii_shield")
    from src.pii_shield import PIIShieldClient as PIIShield

    shield = PIIShield(enabled=True)
    result = shield.sanitize_text("Contact alice@example.com today")
    assert "alice@example.com" not in result.sanitized_text, (
        "email survived in-process redaction: {!r}".format(result.sanitized_text)
    )


# ------------------------------------- 3. it runs without an endpoint at all

def test_sanitization_happens_with_no_endpoint_configured():
    """The behaviour change that makes this worth doing.

    Sanitization used to require `self.endpoint` to be set, and the field is
    documented as an HTTP endpoint, so with no endpoint nothing ran. That is
    why PII-Shield was not running in real CodeGuard runs. WASM needs no
    endpoint, so the condition is gone.
    """
    pytest.importorskip("pii_shield")
    from src.pii_shield import PIIShieldClient as PIIShield

    shield = PIIShield(enabled=True)          # no endpoint anywhere
    assert getattr(shield, "endpoint", None) in (None, ""), (
        "an endpoint is still being carried"
    )
    result = shield.sanitize_text("Contact alice@example.com today")
    assert "alice@example.com" not in result.sanitized_text, (
        "no endpoint means no sanitization again -- the defect that made "
        "PII-Shield a no-op in production"
    )


def test_an_existing_workflow_passing_an_endpoint_does_not_break():
    """Never break the user. Workflows in the wild may still set
    pii_shield_endpoint. The value is now meaningless, but the run must
    proceed and still sanitize rather than raising on an unexpected kwarg.
    """
    pytest.importorskip("pii_shield")
    from src.pii_shield import PIIShieldClient as PIIShield

    shield = PIIShield(enabled=True, endpoint="https://pii.example.com/v1")
    result = shield.sanitize_text("Contact alice@example.com today")
    assert "alice@example.com" not in result.sanitized_text, (
        "a legacy endpoint input broke sanitization"
    )


def test_fail_closed_still_fails_closed():
    """A sanitizer outage must never silently emit raw text. The transport
    changed; that property must not have."""
    pytest.importorskip("pii_shield")
    from src.pii_shield import PIIShieldClient as PIIShield

    shield = PIIShield(enabled=True, fail_closed=True)

    def explode(_text):
        raise RuntimeError("engine unavailable")

    shield._redact = explode                       # type: ignore[attr-defined]
    with pytest.raises(Exception):
        shield.sanitize_text("Contact alice@example.com today")


def test_disabled_shield_is_still_a_passthrough():
    """Regression on the one behaviour that must not change: with the
    feature off, text goes through untouched."""
    pytest.importorskip("pii_shield")
    from src.pii_shield import PIIShieldClient as PIIShield

    shield = PIIShield(enabled=False)
    text = "Contact alice@example.com today"
    assert shield.sanitize_text(text).sanitized_text == text
