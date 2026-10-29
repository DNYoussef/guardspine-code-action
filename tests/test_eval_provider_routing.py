"""Eval harness provider routing (plan design item 7).

A Concentrate key must reach only api.concentrate.ai: in key loading, in the
preflight and in every review call of a sample. The OpenRouter path keeps its
v2.7.4 behaviour. All network traffic here is mocked.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

import run_eval  # noqa: E402
from src.analyzer import AI_REVIEW_ENVELOPE_KEY, AI_REVIEW_SCHEMA_VERSION  # noqa: E402

CN_KEY = "sk-cn-v1-EVALSENTINEL000000000000"
OR_KEY = "sk-or-v1-EVALSENTINEL0000000000"
SPECS = ["concentrate/deepinfra/mimo-v2.6-pro", "concentrate/deepinfra/glm-5.3"]


def _review():
    return json.dumps({AI_REVIEW_ENVELOPE_KEY: {
        "schema_version": AI_REVIEW_SCHEMA_VERSION, "summary": "s", "intent": "bugfix",
        "concerns": ["c"], "risk_assessment": "request_changes", "confidence": 0.9,
        "rubric_scores": {k: None for k in (
            "security_impact", "code_quality", "test_coverage", "documentation", "rollback_safety")}}})


class FakeUrlopen:
    """Records every urllib request the preflight makes."""

    def __init__(self, body):
        self.urls, self.headers, self.body = [], [], body

    def __call__(self, req, timeout=None):
        self.urls.append(req.full_url)
        self.headers.append(dict(req.header_items()))
        body = self.body

        class Resp:
            headers = {"x-concentrate-cost": "0.000001"}

            def read(self):
                return body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return Resp()


def test_concentrate_key_loads_from_its_own_variable(monkeypatch, tmp_path):
    monkeypatch.setattr(run_eval, "_EVAL", tmp_path)
    monkeypatch.setenv("OPENROUTER_API_KEY", OR_KEY)
    monkeypatch.setenv("CONCENTRATE_API_KEY", CN_KEY)
    assert run_eval.load_api_key("concentrate") == CN_KEY
    assert run_eval.load_api_key("openrouter") == OR_KEY
    assert run_eval.load_api_key() == OR_KEY          # default unchanged


def test_concentrate_preflight_contacts_only_concentrate():
    fake = FakeUrlopen(json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode())
    with patch.object(run_eval, "_open_no_redirect", fake), patch.object(urllib.request, "urlopen", fake):
        assert run_eval._preflight_api_key(CN_KEY, "L2", provider="concentrate", models=SPECS)
    assert fake.urls == ["https://api.concentrate.ai/v1/chat/completions"]
    assert fake.headers[0]["Authorization"] == f"Bearer {CN_KEY}"


def test_openrouter_preflight_is_unchanged():
    fake = FakeUrlopen(json.dumps({"data": {"usage": 0, "limit": None}}).encode())
    with patch.object(urllib.request, "urlopen", fake):
        assert run_eval._preflight_api_key(OR_KEY, "L2")
    assert fake.urls == ["https://openrouter.ai/api/v1/auth/key"]


def test_concentrate_preflight_refuses_redirects():
    opener = run_eval._no_redirect_opener()
    handler = next(h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
    req = urllib.request.Request("https://api.concentrate.ai/v1/chat/completions")
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(req, None, 307, "redirect", {}, "https://evil.example/")


def test_make_analyzer_builds_pinned_concentrate_models():
    a = run_eval.make_analyzer(CN_KEY, "L2", provider="concentrate", models=SPECS)
    assert a.models == [("concentrate", "deepinfra/mimo-v2.6-pro"), ("concentrate", "deepinfra/glm-5.3")]
    assert a.openrouter_key is None


def test_make_analyzer_openrouter_default_unchanged():
    a = run_eval.make_analyzer(OR_KEY, "L2")
    assert [p for p, _ in a.models] == ["openrouter"] * 3


def test_concentrate_requires_explicit_models():
    with pytest.raises(SystemExit):
        run_eval.make_analyzer(CN_KEY, "L2", provider="concentrate", models=[])


def test_every_request_of_a_full_sample_goes_to_concentrate(tmp_path):
    seen = []

    def gateway(request):
        seen.append(request)
        body = {"id": "x", "object": "chat.completion", "created": 0, "model": json.loads(request.content)["model"],
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": _review()}}]}
        return httpx.Response(200, json=body, headers={"x-concentrate-cost": "0.001"})

    sample = tmp_path / "vulnerable" / "sqli.patch"
    sample.parent.mkdir()
    sample.write_text("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n"
                      "-x = run(q, (n,))\n+x = run(f\"select '{n}'\")\n", encoding="utf-8")
    a = run_eval.make_analyzer(CN_KEY, "L2", provider="concentrate", models=SPECS)
    a._concentrate_transport = httpx.MockTransport(gateway)
    run_eval.run_sample(sample, "hand-crafted", a, run_eval.RiskClassifier(rubric="default"),
                        run_eval.DecisionEngine(policy="standard"), forced_tier="L2")
    assert len(seen) == 2
    for req in seen:
        assert req.url.host == "api.concentrate.ai"
        assert req.headers["authorization"] == f"Bearer {CN_KEY}"
        assert "concentrate/" + json.loads(req.content)["model"] in SPECS


@pytest.mark.parametrize("bad", [
    ["concentrate/moonshot/kimi-k3"],
    ["concentrate/kimi-k3"],
    ["concentrate/deepinfra/mimo-v2.6-pro", "concentrate/zai/glm-5.3"],
    ["deepinfra/mimo-v2.6-pro"],
    [],
])
def test_invalid_specs_are_rejected_before_any_request(bad):
    fake = FakeUrlopen(b"{}")
    with patch.object(run_eval, "_open_no_redirect", fake), patch.object(urllib.request, "urlopen", fake):
        assert run_eval._preflight_api_key(CN_KEY, "L2", provider="concentrate", models=bad) is False
    assert fake.urls == []


def test_eval_result_records_skipped_models(tmp_path):
    sample = tmp_path / "clean" / "ok.patch"
    sample.parent.mkdir()
    sample.write_text(chr(10).join(["diff --git a/a.py b/a.py", "--- a/a.py", "+++ b/a.py",
                                     "@@ -1 +1 @@", "-x = 1", "+x = 2", ""]), encoding="utf-8")
    a = run_eval.make_analyzer("", "L2", provider="concentrate", models=SPECS)
    r = run_eval.run_sample(sample, "hand-crafted", a, run_eval.RiskClassifier(rubric="default"),
                            run_eval.DecisionEngine(policy="standard"), forced_tier="L2")
    assert r.models_skipped == 2


class EchoingUrlopen(FakeUrlopen):
    """A preflight response whose cost header echoes whatever we choose."""

    def __init__(self, body, cost_header):
        super().__init__(body)
        self.cost_header = cost_header

    def __call__(self, req, timeout=None):
        resp = super().__call__(req, timeout)
        resp.headers = {"x-concentrate-cost": self.cost_header}
        return resp


@pytest.mark.parametrize("header", [CN_KEY, f"0.001 {CN_KEY}", "nan", "-1", "inf"])
def test_preflight_never_prints_a_non_numeric_cost_header(header, capsys):
    fake = EchoingUrlopen(b"{}", header)
    with patch.object(run_eval, "_open_no_redirect", fake):
        assert run_eval._preflight_api_key(CN_KEY, "L2", provider="concentrate", models=SPECS)
    out = capsys.readouterr().out
    assert CN_KEY not in out and "unreported" in out


def test_preflight_prints_a_valid_numeric_cost(capsys):
    # Positive control: the same capture shows the header when it is a real number.
    fake = EchoingUrlopen(b"{}", "0.000123")
    with patch.object(run_eval, "_open_no_redirect", fake):
        run_eval._preflight_api_key(CN_KEY, "L2", provider="concentrate", models=SPECS)
    assert "0.000123 USD" in capsys.readouterr().out


@pytest.mark.parametrize("tier", [None, "L1", "L2", "L3"])
@pytest.mark.parametrize("specs", [
    ["concentrate/deepinfra/mimo-v2.6-pro", "deepinfra/glm-5.3"],
    ["concentrate/deepinfra/mimo-v2.6-pro", "concentrate/moonshot/kimi-k3"],
])
def test_mixed_or_invalid_candidate_lists_are_rejected_at_construction(tier, specs):
    with pytest.raises(SystemExit):
        run_eval.make_analyzer(CN_KEY, tier, provider="concentrate", models=specs)


def test_more_than_three_valid_candidates_is_rejected_not_truncated():
    four = SPECS + ["concentrate/deepinfra/kimi-k3", "concentrate/fireworks/deepseek-v4-pro"]
    with pytest.raises(SystemExit):
        run_eval.make_analyzer(CN_KEY, None, provider="concentrate", models=four)
