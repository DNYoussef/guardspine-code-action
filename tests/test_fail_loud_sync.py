"""Gate: the action must FAIL LOUD when the evidence bundle does not durably
land in the GuardSpine backend. Today it swallows 4xx/5xx into a ::warning:: and
still exits green, so a broken governance loop ships as a passing check. This
gate is fail-first: it goes red against the current entrypoint and green only
once sync failure is fatal AND wired into main()'s exit.

Hermetic: no network (urlopen mocked). Canary-asserted: asserts the exact
failure signal (None return / helper verdict / wired sys.exit), never "a warning
was printed".
"""
import io
import re
import urllib.error
from pathlib import Path

import pytest

import entrypoint


def _http_error(code: int, body: bytes = b'{"detail":["Bundle missing signatures"]}'):
    return urllib.error.HTTPError(
        url="https://api.guardspine.ai/api/v1/bundles/import",
        code=code, msg="err", hdrs=None, fp=io.BytesIO(body),
    )


class _Resp:
    def __init__(self, body: bytes):
        self._b = body
    def read(self):
        return self._b
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def test_post_to_backend_returns_parsed_body_on_2xx(monkeypatch):
    monkeypatch.setattr(
        entrypoint.urllib.request, "urlopen",
        lambda *a, **k: _Resp(b'{"verified": true, "bundle_id": "b-1"}'),
    )
    result = entrypoint._post_to_backend("https://api.x", "k", "/bundles/import", {})
    # must expose the response so callers can check verified -- not a bare bool
    assert isinstance(result, dict) and result.get("verified") is True


def test_post_to_backend_signals_failure_on_http_error(monkeypatch):
    def _raise(*a, **k):
        raise _http_error(422)
    monkeypatch.setattr(entrypoint.urllib.request, "urlopen", _raise)
    result = entrypoint._post_to_backend("https://api.x", "k", "/bundles/import", {})
    assert result is None  # a swallowed False is not enough; failure must be unambiguous


def test_bundle_sync_failed_verdict_is_strict():
    """STRICT: only an explicit verified: True is success. The backend contract
    guarantees a 2xx carries verified (unverified imports 422), so every other
    shape means the evidence did not provably land."""
    f = entrypoint._bundle_sync_failed
    assert f({"verified": True}) is False     # the only success
    assert f(None) is True                    # 4xx/5xx/unreachable
    assert f({"verified": False}) is True
    assert f({}) is True                      # missing field
    assert f({"verified": None}) is True
    assert f({"verified": 0}) is True
    assert f({"verified": "false"}) is True   # truthy string is not True
    assert f({"verified": 1}) is True         # 1 is not True (bool identity)
    assert f("ok") is True                    # non-dict body


def _main_src():
    src = Path(entrypoint.__file__).read_text(encoding="utf-8")
    return src[src.index("def main("):]


# NOTE: these are source canaries, not an execution of main() -- running main()
# end-to-end needs the full GitHub mock surface; the live prod smoke gate
# (Tier 0.2) covers real execution. Each canary pins one behavior that a
# refactor could silently drop.

def test_sync_failure_is_wired_into_main_exit():
    main_src = _main_src()
    assert "fail_on_dashboard_sync_error" in main_src
    assert "_bundle_sync_failed(" in main_src  # the verdict helper is actually called
    # the sync-failure verdict gates a fatal exit (escape hatch: the same guard
    # means fail_on_dashboard_sync_error=false skips the exit)
    assert re.search(
        r"fail_on_dashboard_sync_error and dashboard_sync_failed[\s\S]{0,500}sys\.exit\(1\)",
        main_src,
    )


def test_auto_merge_is_guarded_by_sync_failure():
    """A PR whose governance record never landed must not auto-merge: the
    sync-failure guard must appear between the auto_merge condition and the
    _auto_merge call."""
    main_src = _main_src()
    m = re.search(
        r"if auto_merge[\s\S]{0,800}?_auto_merge\(pr", main_src
    )
    assert m, "auto-merge call site not found"
    assert "dashboard_sync_failed" in m.group(0)


def test_partial_sync_config_counts_as_failure():
    """url XOR key set -> sync was intended but cannot happen; must flag."""
    main_src = _main_src()
    assert re.search(
        r"elif guardspine_api_url or guardspine_api_key:[\s\S]{0,300}dashboard_sync_failed = True",
        main_src,
    )


def test_approvals_sync_stays_non_fatal():
    """/approvals failure must never set dashboard_sync_failed."""
    main_src = _main_src()
    approvals = re.search(r"\"/approvals\", approval_payload\)[\s\S]{0,200}", main_src)
    assert approvals and "dashboard_sync_failed" not in approvals.group(0)
