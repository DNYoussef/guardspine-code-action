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


# --------------------------------------------- G4 / G12a / G9 through the real entrypoint
#
# The entrypoint runs for real with the real DiffAnalyzer; only GitHub, the PR
# diff fetch and the rubric classifier are stubbed, and the Concentrate
# transport is a MockTransport. Comments, SARIF and the evidence bundle are
# produced by the production renderers and read back from where they land.

FORK_EVENT = {"pull_request": {"number": 7, "head": {"repo": {"fork": True, "full_name": "someone/r"}}},
              "sender": {"login": "outsider"}}
DEPENDABOT_EVENT = {"pull_request": {"number": 7, "head": {"repo": {"fork": False, "full_name": "o/r"}}},
                    "sender": {"login": "dependabot[bot]"}}
TRUSTED_EVENT = {"pull_request": {"number": 7, "head": {"repo": {"fork": False, "full_name": "o/r"}}},
                 "sender": {"login": "maintainer"}}


def _run_real_entrypoint(event, gateway, extra_env=None, finding_message="Builds SQL with string formatting"):
    from entrypoint import main

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

        # Fields the governance record in the bundle reads.
        requested_config_packs = []
        loaded_config_packs = []
        skipped_config_packs = {}
        fallback_applied = False

        def __init__(self, *args, **kwargs):
            pass

        def rubric_prompt_packs(self):
            return []

        def classify(self, analysis):
            return {"risk_tier": "L2", "risk_drivers": [], "scores": {}, "rationale": "r",
                    "findings": [{"severity": "high", "zone": "database", "file": "app/users.py",
                                  "line": 1, "message": finding_message, "rule_id": "sql-format"}]}

    analyzers = []

    class TransportAnalyzer(DiffAnalyzer):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._concentrate_transport = httpx.MockTransport(gateway)
            analyzers.append(self)

    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        ev = ws / "event.json"
        ev.write_text(json.dumps(event), encoding="utf-8")
        pr = MagicMock(number=7, title="t", state="open", mergeable=True)
        pr.html_url = "https://github.com/o/r/pull/7"
        pr.user.login = "u"
        pr.base.sha = "basesha"
        pr.head.sha = "headsha"
        pr.get_issue_comments.return_value = []
        repo = MagicMock()
        repo.get_pull.return_value = pr
        gh = MagicMock()
        gh.get_repo.return_value = repo
        env = {"GITHUB_WORKSPACE": str(ws), "GITHUB_EVENT_PATH": str(ev), "GITHUB_REPOSITORY": "o/r",
               "GITHUB_SHA": "abc1234", "GITHUB_REF": "refs/pull/7/head", "INPUT_GITHUB_TOKEN": "token",
               "INPUT_POST_COMMENT": "true", "INPUT_GENERATE_BUNDLE": "true", "INPUT_UPLOAD_SARIF": "true",
               "INPUT_AUTO_MERGE": "false", "INPUT_FAIL_ON_DASHBOARD_SYNC_ERROR": "false",
               "INPUT_MODEL_1": SPEC, **(extra_env or {})}
        out, err = io.StringIO(), io.StringIO()
        saved = {k: os.environ.pop(k) for k in ("INPUT_CONCENTRATE_API_KEY", "CONCENTRATE_API_KEY")
                 if k in os.environ}
        try:
            with patch.dict(os.environ, env, clear=False), \
                    patch("entrypoint.Github", return_value=gh), \
                    patch("entrypoint.fetch_pr_diff", return_value=DIFF), \
                    patch("entrypoint.DiffAnalyzer", TransportAnalyzer), \
                    patch("entrypoint.RiskClassifier", StubClassifier), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                with pytest.raises(SystemExit):
                    main()
        finally:
            os.environ.update(saved)
        comments = [c.args[0] for c in pr.create_issue_comment.call_args_list]
        sarif = ws / "guardspine-results.sarif"
        bundles = sorted((ws / ".guardspine" / "bundles").glob("*.json"))
        return {
            "analyzer": analyzers[0] if analyzers else None,
            "log": out.getvalue() + err.getvalue(),
            "comment": "\n".join(comments),
            "sarif": sarif.read_text(encoding="utf-8") if sarif.exists() else "",
            "bundle": "\n".join(b.read_text(encoding="utf-8") for b in bundles),
        }


def _leaks(run):
    """The one leak oracle used for clean runs and for the planted control."""
    return [(sink, s) for sink in ("log", "comment", "sarif", "bundle")
            for s in (KEY, ERROR_SENTINEL) if s in run[sink]]


@pytest.mark.parametrize("event", [FORK_EVENT, DEPENDABOT_EVENT, TRUSTED_EVENT],
                         ids=["fork", "dependabot", "trusted-missing-secret"])
def test_no_key_runs_send_nothing_and_say_so(event):
    gw = Gateway("ok")
    run = _run_real_entrypoint(event, gw)
    assert gw.requests == []
    assert run["analyzer"].models == []
    assert "AI review skipped" in run["log"] and "no Concentrate key" in run["log"]
    assert "skipped (no provider key in this run)" in run["comment"]
    assert '"models_skipped"' in run["bundle"]


def test_key_present_run_reaches_only_concentrate_through_the_real_entrypoint():
    # Positive control for the zero-request runs above.
    gw = Gateway("ok")
    run = _run_real_entrypoint(TRUSTED_EVENT, gw, {"INPUT_CONCENTRATE_API_KEY": KEY})
    assert len(gw.requests) >= 1
    assert all(str(r.url) == "https://api.concentrate.ai/v1/chat/completions" for r in gw.requests)
    assert all(json.loads(r.content)["model"] == PINNED for r in gw.requests)
    assert '"provider": "concentrate"' in run["bundle"]


def test_key_and_gateway_error_body_reach_no_sink():
    run = _run_real_entrypoint(TRUSTED_EVENT, Gateway("500"), {"INPUT_CONCENTRATE_API_KEY": KEY})
    assert run["comment"] and run["sarif"] and run["bundle"]   # every sink was produced
    assert _leaks(run) == []


def test_the_leak_oracle_rejects_a_planted_leak_in_the_rendered_sinks():
    run = _run_real_entrypoint(TRUSTED_EVENT, Gateway("500"), {"INPUT_CONCENTRATE_API_KEY": KEY},
                               finding_message=f"planted {KEY} and {ERROR_SENTINEL}")
    leaked_sinks = {sink for sink, _ in _leaks(run)}
    assert {"sarif", "bundle"} <= leaked_sinks


# ------------------------------------------------------ coverage and identity edges

def test_partial_availability_marks_coverage_incomplete():
    a = DiffAnalyzer(openrouter_key="k", model_1="anthropic/claude-sonnet-4.5",
                     model_2="concentrate/deepinfra/glm-5.3")
    with patch.object(a, "_call_openrouter", return_value=(_review_json(), {"model_id": "m"})):
        result = a.analyze(DIFF, tier_override="L2")
    cov = result["review_coverage"]
    assert cov["complete"] is False and cov["skipped"] == 1 and cov["succeeded"] == 1


def test_unparseable_diff_still_reports_skipped_models():
    a = _analyzer(concentrate_key=None)
    with patch("src.analyzer.PatchSet", side_effect=ValueError("bad diff")):
        result = a.analyze("not a diff")
    assert result["multi_model_review"]["models_skipped"] == a.models_skipped
    assert result["review_coverage"]["complete"] is False


def test_null_content_keeps_the_reported_identity():
    other = "deepinfra/glm-5.3"

    def gateway(request):
        body = {"id": "x", "object": "chat.completion", "created": 0, "model": other,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": None}}]}
        return httpx.Response(200, json=body, headers={"x-concentrate-cost": "0.001"})

    a = _analyzer(gateway)
    review = a.analyze(DIFF, tier_override="L1")["multi_model_review"]["reviews"][0]
    assert review["model_id"] == other and review["model_name"] == PINNED
    assert review.get("parse_error") or review.get("schema_error")
    prev = [{"summary": "s", "concerns": [], "risk_assessment": "approve", "model_name": PINNED}]
    (cross,) = a._parallel_crosscheck([("concentrate", PINNED)], prev, DIFF, round_num=2)
    assert cross["model_id"] == other


def test_outer_review_failure_records_not_reported():
    a = _analyzer(Gateway("ok"))
    with patch.object(a, "_get_model_review", side_effect=RuntimeError("boom")):
        (r,) = a._parallel_review([("concentrate", PINNED)], DIFF, [], "default", False)
    assert r["model_id"] == "not reported"


def test_legacy_outer_failure_shape_unchanged():
    a = DiffAnalyzer(openrouter_key="k", model_1="anthropic/claude-sonnet-4.5")
    with patch.object(a, "_get_model_review", side_effect=RuntimeError("boom")):
        (r,) = a._parallel_review([("openrouter", "anthropic/claude-sonnet-4.5")], DIFF, [], "default", False)
    assert "model_id" not in r


def test_comment_note_names_skipped_models():
    from src.pr_commenter import PRCommenter
    note = PRCommenter._coverage_note({"attempted": 0, "succeeded": 0, "complete": False, "skipped": 2})
    assert "2 configured model(s) skipped" in note
    assert PRCommenter._coverage_note({"attempted": 1, "succeeded": 1, "complete": True}) == ""


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


def _simulated_metadata_tags(workflow_text, ref, sha="abc1234"):
    """Tags docker/metadata-action v5 would emit for the workflow's rules on one event.

    Mirrors the documented rule semantics for the rule types this workflow can
    contain: semver {{version}}/{{major}}, sha, ref event=branch, and the
    automatic latest tag (on for a non-prerelease semver tag unless flavor
    latest=false). Rules of any other type fail the check rather than being ignored.
    """
    import yaml
    steps = yaml.safe_load(workflow_text)["jobs"]["build-and-push"]["steps"]
    meta = next(s["with"] for s in steps if "metadata-action" in s.get("uses", ""))
    rules = [r.strip() for r in meta["tags"].splitlines() if r.strip()]
    flavor = (meta.get("flavor") or "").replace(" ", "")
    tags = set()
    version = ref[len("refs/tags/v"):] if ref.startswith("refs/tags/v") else None
    prerelease = bool(version and "-" in version)
    for rule in rules:
        if rule == "type=semver,pattern={{version}}":
            if version:
                tags.add(version)
        elif rule == "type=semver,pattern={{major}}":
            if version and not prerelease:
                tags.add(version.split(".")[0])
        elif rule == "type=sha":
            tags.add("sha-" + sha[:7])
        elif rule == "type=ref,event=branch":
            if ref.startswith("refs/heads/"):
                tags.add(ref[len("refs/heads/"):])
        else:
            raise AssertionError(f"unmodelled metadata rule: {rule}")
    if version and not prerelease and "latest=false" not in flavor:
        tags.add("latest")
    return tags


FLOATING = {"2", "latest", "main"}
EVENTS = ("refs/tags/v2.8.0-rc.1", "refs/tags/v2.8.0", "refs/heads/main")


def test_docker_publish_holds_every_floating_alias():
    wf = (ROOT / ".github" / "workflows" / "docker-publish.yml").read_text(encoding="utf-8")
    for ref in EVENTS:
        assert not (_simulated_metadata_tags(wf, ref) & FLOATING), ref
    assert _simulated_metadata_tags(wf, "refs/tags/v2.8.0") == {"2.8.0", "sha-abc1234"}


NL = chr(10)
VERSION_RULE = "            type=semver,pattern={{version}}" + NL


@pytest.mark.parametrize("mutation", [
    (VERSION_RULE, VERSION_RULE + "            type=semver,pattern={{major}}" + NL),
    ("            latest=false" + NL, "            latest=auto" + NL),
    (VERSION_RULE, "            type=ref,event=branch" + NL + VERSION_RULE),
])
def test_the_alias_check_rejects_each_restored_rule(mutation):
    wf = (ROOT / ".github" / "workflows" / "docker-publish.yml").read_text(encoding="utf-8")
    old, new = mutation
    assert wf.count(old) == 1
    bad = wf.replace(old, new)
    assert any(_simulated_metadata_tags(bad, ref) & FLOATING for ref in EVENTS)


# ----------------------------------------- sealed provenance on every failure path

OTHER = "deepinfra/glm-5.3"


def _gateway_returning(content, model=OTHER):
    def gateway(request):
        body = {"id": "x", "object": "chat.completion", "created": 0,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": content}}]}
        if model is not None:
            body["model"] = model
        return httpx.Response(200, json=body, headers={"x-concentrate-cost": "0.001"})
    return gateway


def _bad_verdict():
    data = json.loads(_review_json())
    data[AI_REVIEW_ENVELOPE_KEY]["risk_assessment"] = []
    return json.dumps(data)


CASES = {
    "http-500": (Gateway("500"), "not reported", True),
    "timeout": (Gateway("timeout"), "not reported", True),
    "no-model": (Gateway("ok-no-model"), "not reported", False),
    "null-content": (_gateway_returning(None), OTHER, True),
    "bad-verdict": (_gateway_returning(_bad_verdict()), OTHER, True),
    "success": (_gateway_returning(_review_json()), OTHER, False),
}


def _bundle_for(gateway):
    from src.bundle_generator import BundleGenerator
    a = _analyzer(gateway)
    result = a.analyze(DIFF, tier_override="L1")
    bundle = BundleGenerator().create_bundle(pr=_pr(), analysis=result, risk_result={
        "risk_tier": "L1", "risk_drivers": [], "findings": [], "scores": {}, "rationale": "r"},
        repository="o/r", commit_sha="abc1234")
    sealed = next(e for e in bundle["events"] if e["event_type"] == "analysis_completed")["data"]["reviews_sealed"]
    snapshot = bundle["analysis_snapshot"]["multi_model_review"]["reviews"]
    return sealed, snapshot


@pytest.mark.parametrize("case", list(CASES))
def test_sealed_entry_and_snapshot_each_carry_honest_identity(case):
    gateway, expected_id, failed = CASES[case]
    sealed, snapshot = _bundle_for(gateway)
    (entry,) = sealed
    assert entry["provider"] == "concentrate" and entry["model_name"] == PINNED
    assert entry["model_id"] == expected_id
    assert entry["serving_host"] == "not exposed"
    assert entry["failed"] is failed
    (review,) = snapshot
    assert review["model_id"] == expected_id and review["serving_host"] == "not exposed"


def test_malformed_verdict_keeps_identity_in_crosscheck_too():
    a = _analyzer(_gateway_returning(_bad_verdict()))
    prev = [{"summary": "s", "concerns": [], "risk_assessment": "approve", "model_name": PINNED}]
    (cross,) = a._parallel_crosscheck([("concentrate", PINNED)], prev, DIFF, round_num=2)
    assert cross["model_id"] == OTHER and cross["serving_host"] == "not exposed"
    assert cross.get("schema_error")


def test_legacy_failed_reviews_are_still_not_sealed():
    from src.bundle_generator import BundleGenerator
    a = DiffAnalyzer(openrouter_key="k", model_1="anthropic/claude-sonnet-4.5")
    with patch.object(a, "_call_openrouter", side_effect=RuntimeError("down")):
        result = a.analyze(DIFF, tier_override="L1")
    bundle = BundleGenerator().create_bundle(pr=_pr(), analysis=result, risk_result={
        "risk_tier": "L1", "risk_drivers": [], "findings": [], "scores": {}, "rationale": "r"},
        repository="o/r", commit_sha="abc1234")
    sealed = next(e for e in bundle["events"] if e["event_type"] == "analysis_completed")["data"]["reviews_sealed"]
    assert sealed == []


def test_any_failure_after_the_response_keeps_the_reported_identity():
    # Force processing to raise after the gateway has answered, on both review paths.
    a = _analyzer(_gateway_returning(_review_json()))
    with patch.object(a, "_parse_review_response", side_effect=RuntimeError("late failure")):
        review = a.analyze(DIFF, tier_override="L1")["multi_model_review"]["reviews"][0]
        prev = [{"summary": "s", "concerns": [], "risk_assessment": "approve", "model_name": PINNED}]
        (cross,) = a._parallel_crosscheck([("concentrate", PINNED)], prev, DIFF, round_num=2)
    for r in (review, cross):
        assert r.get("error") and r["model_id"] == OTHER and r["serving_host"] == "not exposed"
