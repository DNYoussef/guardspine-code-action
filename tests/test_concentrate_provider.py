"""Gates for the Concentrate provider (plan gates G4, G5, G6, G9, G12a, G13a).

Written before the implementation. Every network probe runs against an
httpx.MockTransport injected through DiffAnalyzer._concentrate_transport, so
nothing here can reach the real gateway or spend money.
"""

import contextlib
import io
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from src.analyzer import (  # noqa: E402
    AI_REVIEW_ENVELOPE_KEY,
    AI_REVIEW_SCHEMA_VERSION,
    DiffAnalyzer,
)

KEY = "sk-cn-v1-TESTSENTINELKEY0123456789"
ERROR_SENTINEL = "ZZGATEWAYERRORBODYZZ"
SPEC = "concentrate/deepinfra/mimo-v2.6-pro"
PINNED = "deepinfra/mimo-v2.6-pro"
DIFF = (
    "diff --git a/app/users.py b/app/users.py\n"
    "--- a/app/users.py\n+++ b/app/users.py\n"
    "@@ -1,1 +1,1 @@\n"
    "-cur = conn.execute('SELECT 1 WHERE n = ?', (n,))\n"
    "+cur = conn.execute(f\"SELECT 1 WHERE n = '{n}'\")\n"
)


def _review_json(risk="request_changes", concern="SQL injection in app/users.py line 1"):
    return json.dumps({AI_REVIEW_ENVELOPE_KEY: {
        "schema_version": AI_REVIEW_SCHEMA_VERSION,
        "summary": "Builds SQL with an f-string.",
        "intent": "bugfix",
        "concerns": [concern],
        "risk_assessment": risk,
        "confidence": 0.9,
        "rubric_scores": {k: None for k in (
            "security_impact", "code_quality", "test_coverage", "documentation", "rollback_safety")},
    }})


class Gateway:
    """A fake Concentrate. Records every request; behaviour is a list consumed in order."""

    def __init__(self, *behaviours):
        self.behaviours = list(behaviours) or ["ok"]
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        b = self.behaviours.pop(0) if len(self.behaviours) > 1 else self.behaviours[0]
        if b == "ok":
            return self._ok(model=PINNED, cost="0.0010")
        if b == "ok-no-model":
            return self._ok(model=None, cost="0.0010")
        if b == "ok-no-cost":
            return self._ok(model=PINNED, cost=None)
        if b == "redirect":
            return httpx.Response(307, headers={"location": "https://evil.example/v1/chat/completions"})
        if b == "500":
            return httpx.Response(500, json={"error": {"message": ERROR_SENTINEL}},
                                  headers={"x-concentrate-cost": "0.0005"})
        if b == "timeout":
            raise httpx.ReadTimeout("timed out", request=request)
        raise AssertionError(b)

    @staticmethod
    def _ok(model, cost):
        body = {"id": "x", "object": "chat.completion", "created": 0,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": _review_json()}}]}
        if model is not None:
            body["model"] = model
        headers = {} if cost is None else {"x-concentrate-cost": cost}
        return httpx.Response(200, json=body, headers=headers)


def _analyzer(gateway=None, **kw):
    kw.setdefault("concentrate_key", KEY)
    kw.setdefault("model_1", SPEC)
    a = DiffAnalyzer(**kw)
    if gateway is not None:
        a._concentrate_transport = httpx.MockTransport(gateway)
    return a


def _pr():
    pr = MagicMock()
    pr.number = 7
    pr.title = "t"
    pr.user.login = "u"
    pr.html_url = "https://github.com/o/r/pull/7"
    pr.base.sha = "basesha"
    pr.head.sha = "headsha"
    return pr


# ---------------------------------------------------------------- G4 routing

def test_concentrate_spec_routes_to_concentrate():
    a = _analyzer()
    assert a.models == [("concentrate", PINNED)]


@pytest.mark.parametrize("extra", [
    {"openrouter_key": "sk-or-x"},
    {"ollama_host": "http://localhost:11434"},
    {"openai_key": "sk-x", "anthropic_key": "sk-ant-x"},
])
def test_concentrate_spec_never_falls_to_another_provider(extra):
    for spec in (SPEC, "concentrate/deepinfra/qwen3.8-27b", "concentrate/fireworks/deepseek-v4-pro"):
        a = _analyzer(model_1=spec, **extra)
        assert [p for p, _ in a.models] == ["concentrate"], spec


@pytest.mark.parametrize("bad", [
    "concentrate/mimo-v2.6-pro",            # no host pin
    "concentrate/moonshot/kimi-k3",         # host not on the allowlist
    "concentrate/zai/glm-5.3",              # first-party host
    "concentrate/deepinfra/",               # empty slug
    "concentrate//mimo-v2.6-pro",           # empty host
    "concentrate/deepinfra/a/b",            # extra segment
    "concentrate/DeepInfra/mimo-v2.6-pro",  # hosts are matched exactly
])
def test_unpinned_or_unapproved_concentrate_spec_is_a_config_error(bad):
    with pytest.raises(ValueError, match="concentrate"):
        _analyzer(model_1=bad)


# Frozen from guardspine-code-action v2.7.4 _parse_model_spec: every existing
# spec must route exactly as before.
LEGACY = [
    ({"openrouter_key": "k"}, "anthropic/claude-sonnet-4.5", ("openrouter", "anthropic/claude-sonnet-4.5")),
    ({"openrouter_key": "k"}, "deepinfra/mimo-v2.6-pro", ("openrouter", "deepinfra/mimo-v2.6-pro")),
    ({"anthropic_key": "k"}, "anthropic/claude-x", ("anthropic", "claude-x")),
    ({"anthropic_key": "k"}, "claude-haiku-4-5-20251001", ("anthropic", "claude-haiku-4-5-20251001")),
    ({"openai_key": "k"}, "gpt-4.1-mini", ("openai", "gpt-4.1-mini")),
    ({"ollama_host": "h"}, "llama3.3", ("ollama", "llama3.3")),
    ({"ollama_host": "h"}, "qwen3-32b", ("ollama", "qwen3-32b")),
    ({"openrouter_key": "k"}, "mimo-v2.6-pro", ("openrouter", "mimo-v2.6-pro")),
    ({}, "mimo-v2.6-pro", ("ollama", "mimo-v2.6-pro")),
    ({}, "concentrate-lookalike", ("ollama", "concentrate-lookalike")),
]


@pytest.mark.parametrize("keys,spec,expected", LEGACY)
def test_existing_specs_route_exactly_as_v2_7_4(keys, spec, expected):
    a = DiffAnalyzer(**keys)
    assert a._parse_model_spec(spec) == expected


# ------------------------------------------------- G12a missing key / forks

def test_missing_key_skips_concentrate_models_visibly_and_sends_nothing():
    gw = Gateway("ok")
    a = _analyzer(gw, concentrate_key=None, model_2="concentrate/deepinfra/glm-5.3")
    assert a.models == []
    assert not a.ai_enabled
    assert [s["model"] for s in a.models_skipped] == [PINNED, "deepinfra/glm-5.3"]
    assert all(s["provider"] == "concentrate" and "no Concentrate key" in s["reason"] for s in a.models_skipped)
    result = a.analyze(DIFF, tier_override="L2")
    assert gw.requests == []
    assert result["multi_model_review"]["models_skipped"] == a.models_skipped


def test_with_key_present_the_capture_sees_requests():
    # Positive control for the zero-request assertion above.
    gw = Gateway("ok")
    _analyzer(gw).analyze(DIFF, tier_override="L1")
    assert len(gw.requests) == 1


# ---------------------------------------------------------- request shape

def test_request_goes_only_to_the_fixed_endpoint_with_the_pinned_model():
    gw = Gateway("ok")
    _analyzer(gw).analyze(DIFF, tier_override="L1")
    (req,) = gw.requests
    assert str(req.url) == "https://api.concentrate.ai/v1/chat/completions"
    assert req.headers["authorization"] == f"Bearer {KEY}"
    assert "http-referer" not in req.headers and "x-title" not in req.headers
    body = json.loads(req.content)
    assert body["model"] == PINNED
    assert body["max_tokens"] == 4000
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True


def test_other_providers_keep_max_tokens_1000():
    a = DiffAnalyzer(openrouter_key="k", model_1="anthropic/claude-sonnet-4.5")
    client = MagicMock()
    client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content=_review_json()))], model="m")
    with patch("openai.OpenAI", return_value=client):
        a._call_openrouter("prompt", "anthropic/claude-sonnet-4.5")
    assert client.chat.completions.create.call_args.kwargs["max_tokens"] == 1000


def test_a_cross_origin_redirect_is_refused_and_nothing_is_resent():
    gw = Gateway("redirect", "ok")
    result = _analyzer(gw).analyze(DIFF, tier_override="L1")
    assert [r.url.host for r in gw.requests] == ["api.concentrate.ai"]
    review = result["multi_model_review"]["reviews"][0]
    assert review.get("error")


# ------------------------------------------------------------ G5 identity

def _review_of(behaviour):
    return _analyzer(Gateway(behaviour)).analyze(DIFF, tier_override="L1")[
        "multi_model_review"]["reviews"][0]


def test_identity_on_success():
    r = _review_of("ok")
    assert (r["provider"], r["model_name"], r["model_id"]) == ("concentrate", PINNED, PINNED)


@pytest.mark.parametrize("behaviour", ["ok-no-model", "500", "timeout"])
def test_gateway_identity_is_not_reported_when_no_response_supplied_it(behaviour):
    r = _review_of(behaviour)
    assert r["provider"] == "concentrate"
    assert r["model_name"] == PINNED              # what we asked for
    assert r["model_id"] == "not reported"        # never the requested slug


def test_crosscheck_failure_keeps_identity_honest():
    a = _analyzer(Gateway("500"))
    prev = [{"summary": "s", "concerns": [], "risk_assessment": "approve", "model_name": PINNED}]
    (r,) = a._parallel_crosscheck([("concentrate", PINNED)], prev, DIFF, round_num=2)
    assert r["model_id"] == "not reported"


def test_legacy_provider_exception_identity_unchanged():
    a = DiffAnalyzer(openrouter_key="k", model_1="anthropic/claude-sonnet-4.5")
    with patch.object(a, "_call_openrouter", side_effect=RuntimeError("down")):
        r = a._get_model_review("openrouter", "anthropic/claude-sonnet-4.5", DIFF, [], "default", False)
    assert r["model_id"] == "anthropic/claude-sonnet-4.5"


def test_the_bundle_seals_concentrate_identity():
    from src.bundle_generator import BundleGenerator
    result = _analyzer(Gateway("ok")).analyze(DIFF, tier_override="L1")
    pr = _pr()
    bundle = BundleGenerator().create_bundle(pr=pr, analysis=result, risk_result={
        "risk_tier": "L1", "risk_drivers": [], "findings": [], "scores": {}, "rationale": "r"},
        repository="o/r", commit_sha="abc1234")
    sealed = json.dumps(bundle, default=str)
    # The hash-sealed review entry carries the three identity fields separately.
    assert (f'"model_name": "{PINNED}", "provider": "concentrate", "model_id": "{PINNED}"') in sealed


# ---------------------------------------------------------------- cost ledger

def test_cost_is_summed_across_every_charged_call():
    a = _analyzer(Gateway("ok", "500"), model_2="concentrate/deepinfra/glm-5.3")
    result = a.analyze(DIFF, tier_override="L2")
    cost = result["multi_model_review"]["concentrate_cost"]
    assert cost["calls"] == 2
    assert cost["total_usd"] == pytest.approx(0.0015)   # the failed call's charge counts
    assert cost["unreported_calls"] == 0


def test_a_missing_cost_header_makes_the_total_unknown_not_zero():
    a = _analyzer(Gateway("ok-no-cost"))
    cost = a.analyze(DIFF, tier_override="L1")["multi_model_review"]["concentrate_cost"]
    assert cost["total_usd"] == "unknown" and cost["unreported_calls"] == 1


def test_deliberation_rounds_are_all_charged():
    gw = Gateway("ok")
    a = _analyzer(gw, model_2="concentrate/deepinfra/glm-5.3", model_3="concentrate/deepinfra/kimi-k3")
    with patch.object(a, "_should_exit_early", return_value=False):
        result = a.analyze(DIFF, tier_override="L3", deliberate=True)
    cost = result["multi_model_review"]["concentrate_cost"]
    assert len(gw.requests) == 9                 # 3 models x 3 rounds
    assert cost["calls"] == 9
    assert cost["total_usd"] == pytest.approx(0.009)


# --------------------------------------------------------------- G9 leakage

def test_key_and_gateway_error_body_reach_no_sink():
    from src.bundle_generator import BundleGenerator
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        a = _analyzer(Gateway("500"))
        result = a.analyze(DIFF, tier_override="L1")
        pr = _pr()
        bundle = BundleGenerator().create_bundle(pr=pr, analysis=result, risk_result={
            "risk_tier": "L1", "risk_drivers": [], "findings": [], "scores": {}, "rationale": "r"},
            repository="o/r", commit_sha="abc1234")
    sinks = out.getvalue() + err.getvalue() + json.dumps(dict(result.items()), default=str) + json.dumps(bundle, default=str)
    assert KEY not in sinks
    assert ERROR_SENTINEL not in sinks


def test_leak_check_can_see_a_planted_leak():
    # Positive control: the same sinks DO show a value we deliberately print.
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        print(KEY)
    assert KEY in out.getvalue()


# ------------------------------------------------- entrypoint wiring (G4/G12a)

def _run_entrypoint(extra_env):
    from entrypoint import main

    captured = {}

    class CaptureAnalyzer(DiffAnalyzer):
        def __init__(self, *args, **kwargs):
            captured["kwargs"] = kwargs
            super().__init__(*args, **kwargs)
            self._concentrate_transport = httpx.MockTransport(lambda r: (_ for _ in ()).throw(
                AssertionError("no request expected in this wiring test")))

        def analyze(self, *args, **kwargs):
            captured["analyzer"] = self
            return {"files_changed": 1, "lines_added": 1, "lines_removed": 0, "files": [],
                    "sensitive_zones": [], "diff_hash": "sha256:x", "models_used": 0,
                    "consensus_risk": "", "agreement_score": 0.0,
                    "multi_model_review": {"models_skipped": self.models_skipped}}

    class StubClassifier:
        @staticmethod
        def discover_builtin_rubrics(_repo_root):
            return {}

        @staticmethod
        def shipped_rubrics():
            from guardspine_prompts import rubric_paths
            return {"default": rubric_paths()["default"]}

        @staticmethod
        def builtin_names(_repo_root):
            return {"default"}

        def __init__(self, *args, **kwargs):
            pass

        def rubric_prompt_packs(self):
            return []

        def classify(self, analysis):
            return {"risk_tier": "L0", "risk_drivers": [], "findings": [], "scores": {}, "rationale": "ok"}

    packet = MagicMock(decision="merge", hard_blocks=[], conditions=[], advisory=[])
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        ev = ws / "event.json"
        ev.write_text(json.dumps({"pull_request": {"number": 7}}), encoding="utf-8")
        pr = MagicMock(number=7, title="t", state="open", mergeable=True)
        repo = MagicMock()
        repo.get_pull.return_value = pr
        gh = MagicMock()
        gh.get_repo.return_value = repo
        env = {"GITHUB_WORKSPACE": str(ws), "GITHUB_EVENT_PATH": str(ev), "GITHUB_REPOSITORY": "o/r",
               "GITHUB_SHA": "abc1234", "GITHUB_REF": "refs/pull/7/head", "INPUT_GITHUB_TOKEN": "token",
               "INPUT_POST_COMMENT": "false", "INPUT_GENERATE_BUNDLE": "false", "INPUT_UPLOAD_SARIF": "false",
               "INPUT_AUTO_MERGE": "false", "INPUT_MODEL_1": SPEC, **extra_env}
        out = io.StringIO()
        with patch.dict(os.environ, env, clear=False), \
                patch("entrypoint.Github", return_value=gh), \
                patch("entrypoint.fetch_pr_diff", return_value=DIFF), \
                patch("entrypoint.DiffAnalyzer", CaptureAnalyzer), \
                patch("entrypoint.RiskClassifier", StubClassifier), \
                patch("entrypoint.DecisionEngine") as engine, \
                patch("entrypoint.render_decision_card", return_value="card"), \
                contextlib.redirect_stdout(out):
            engine.return_value.decide.return_value = packet
            with pytest.raises(SystemExit):
                main()
    return captured, out.getvalue()


def test_entrypoint_passes_the_concentrate_input_to_the_analyzer():
    captured, log = _run_entrypoint({"INPUT_CONCENTRATE_API_KEY": KEY})
    assert captured["kwargs"]["concentrate_key"] == KEY
    assert captured["analyzer"].models == [("concentrate", PINNED)]
    assert KEY not in log


def test_entrypoint_announces_skipped_concentrate_review_without_a_key():
    os.environ.pop("INPUT_CONCENTRATE_API_KEY", None)
    os.environ.pop("CONCENTRATE_API_KEY", None)
    captured, log = _run_entrypoint({})
    assert captured["analyzer"].models == []
    assert "AI review skipped" in log and "no Concentrate key" in log


# ------------------------------------------------------- G6 / G13a config

V274_INPUTS = {
    'risk_threshold': 'L3',
    'rubric': '',
    'github_token': '${{ github.token }}',
    'post_comment': 'true',
    'generate_bundle': 'true',
    'attestation_key': '',
    'attestation_key_id': '',
    'upload_sarif': 'false',
    'fail_on_high_risk': 'false',
    'fail_on_dashboard_sync_error': 'true',
    'openai_api_key': None,
    'anthropic_api_key': None,
    'openrouter_api_key': None,
    'openrouter_model': 'anthropic/claude-sonnet-4.5',
    'ollama_host': None,
    'ollama_model': 'llama3.3',
    'model_1': None,
    'model_2': None,
    'model_3': None,
    'ai_review': 'true',
    'pii_shield_enabled': 'false',
    'pii_shield_mode': 'auto',
    'pii_shield_endpoint': None,
    'pii_shield_api_key': None,
    'pii_shield_timeout': '5',
    'pii_shield_fail_closed': 'true',
    'pii_shield_salt_fingerprint': 'sha256:00000000',
    'pii_safe_regex_list': '[{"pattern": "^[a-f0-9]{40,64}$", "name": "SafeGitSHA"}, {"pattern": "_hash$", "name": "HashFieldSuffix"}]',
    'pii_shield_sanitize_comments': 'true',
    'pii_shield_sanitize_bundle': 'true',
    'pii_shield_sanitize_sarif': 'true',
    'rubrics_dir': '.guardspine/rubrics',
    'risk_policy': None,
    'bundle_dir': '.guardspine/bundles',
    'decision_policy': 'standard',
    'deliberate': 'false',
    'auto_merge': 'false',
    'auto_merge_method': 'squash',
    'guardspine_api_url': None,
    'guardspine_api_key': None,
}


def _action_inputs():
    import yaml
    data = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    return data


def test_existing_action_inputs_keep_their_names_and_defaults():
    inputs = _action_inputs()["inputs"]
    for name, default in V274_INPUTS.items():
        assert name in inputs, name
        assert inputs[name].get("default") == default, name


def test_concentrate_input_is_declared_and_mapped():
    data = _action_inputs()
    assert "default" not in data["inputs"]["concentrate_api_key"]
    assert data["runs"]["env"]["INPUT_CONCENTRATE_API_KEY"] == "${{ inputs.concentrate_api_key }}"


def test_docker_publish_holds_every_floating_alias():
    wf = (ROOT / ".github" / "workflows" / "docker-publish.yml").read_text(encoding="utf-8")
    assert "pattern={{major}}" not in wf
    assert re.search(r"flavor:\s*\|?\s*\n?\s*latest=false", wf)
