"""The evidence bundle must record which humans approved the reviewed commit.

create_bundle could always write approval_granted events, but the Action never
gave it any approvers, so every real bundle was silent about human review.

These also pin the three things that make a review-triggered run safe:
- an approval of an older commit, or one later withdrawn, is not recorded;
- a failed review lookup is recorded as unavailable, not as "nobody approved";
- GITHUB_BASE_REF is only set on pull_request events, so a pull_request_review
  run must recover the base ref from the event. Otherwise the rubric trust
  boundary falls back to the PR's own files.

Run: python -m pytest tests/test_human_approvals.py -q
"""
import copy
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from entrypoint import (
    RubricUnavailableError,
    _auto_merge,
    _restore_approval_records,
    collect_human_approvals,
    main,
)
from src.bundle_generator import BundleGenerator, verify_bundle_chain
from src.pii_shield import PIIShieldClient
from test_entrypoint_pii_shield import _make_env, _make_pii_client, _make_stubs

HEAD = "head-sha-current"
OLD = "head-sha-older"
DIFF = "diff --git a/app.py b/app.py\n+print('hi')\n"
T0 = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


def _review(login, state, commit=HEAD, minutes=0, kind="User", review_id=None):
    return SimpleNamespace(
        id=review_id if review_id is not None else 100 + minutes,
        user=SimpleNamespace(login=login, type=kind),
        state=state,
        commit_id=commit,
        submitted_at=T0 + timedelta(minutes=minutes),
    )


def _pr(reviews, author="author"):
    pr = MagicMock()
    pr.number = 7
    pr.title = "A change"
    pr.created_at = T0
    pr.user = SimpleNamespace(login=author)
    pr.head = SimpleNamespace(sha=HEAD, ref="feature")
    pr.base = SimpleNamespace(ref="main", sha="base-sha")
    pr.get_reviews.return_value = reviews
    return pr


def _collect(pr, analyzed_diff=DIFF, commit_diff=DIFF):
    repo = MagicMock()
    repo.url = "https://api.github.test/repos/o/r"
    repo.get_pull.return_value = pr
    answer = SimpleNamespace(ok=True, text=commit_diff)
    with patch("requests.get", return_value=answer) as get:
        result = collect_human_approvals(repo, 7, HEAD, analyzed_diff)
    _collect.urls = [call.args[0] for call in get.call_args_list]
    return result


def _logins(reviews, **kwargs):
    approvals, status = _collect(_pr(reviews, **kwargs))
    return [a["login"] for a in approvals], status


def test_approval_of_the_current_head_is_recorded_with_its_details():
    approvals, status = _collect(
        _pr([_review("alice", "APPROVED", minutes=5, review_id=55)])
    )
    assert status == "recorded"
    assert approvals == [{
        "login": "alice",
        "review_id": 55,
        "commit_sha": HEAD,
        "approved_at": (T0 + timedelta(minutes=5)).isoformat(),
    }]


def test_no_reviews_is_none_not_unavailable():
    assert _logins([]) == ([], "none")


def test_approval_of_an_older_commit_is_not_recorded():
    assert _logins([_review("alice", "APPROVED", commit=OLD)]) == ([], "none")


def test_changes_requested_after_approval_withdraws_it():
    assert _logins([
        _review("alice", "APPROVED", minutes=1),
        _review("alice", "CHANGES_REQUESTED", minutes=2),
    ]) == ([], "none")


def test_dismissed_approval_is_not_recorded():
    assert _logins([_review("alice", "DISMISSED")]) == ([], "none")


def test_comment_after_approval_does_not_withdraw_it():
    assert _logins([
        _review("alice", "APPROVED", minutes=1),
        _review("alice", "COMMENTED", minutes=2),
    ]) == (["alice"], "recorded")


def test_review_order_comes_from_time_not_api_position():
    assert _logins([
        _review("alice", "CHANGES_REQUESTED", minutes=2),
        _review("alice", "APPROVED", minutes=1),
    ]) == ([], "none")


def test_bots_and_the_author_are_not_human_approvers():
    assert _logins([
        _review("ci-bot[bot]", "APPROVED", kind="Bot", minutes=1),
        _review("author", "APPROVED", minutes=2),
        _review("bob", "APPROVED", minutes=3),
    ]) == (["bob"], "recorded")


def test_deleted_user_and_pending_review_do_not_crash():
    ghost = _review("x", "APPROVED")
    ghost.user = None
    pending = _review("carol", "PENDING")
    pending.submitted_at = None
    assert _logins([ghost, pending]) == ([], "none")


def test_failed_lookup_is_unavailable_and_says_so(capsys):
    pr = _pr([])
    pr.get_reviews.side_effect = RuntimeError("boom-detail")
    assert _collect(pr) == ([], "unavailable")
    out = capsys.readouterr().out
    assert "::warning::" in out and "RuntimeError" in out
    assert "boom-detail" not in out


def _bundle(**kwargs):
    return BundleGenerator().create_bundle(
        pr=_pr([]),
        analysis={"files_changed": 0, "lines_added": 0, "lines_removed": 0,
                  "diff_hash": "sha256:x"},
        risk_result={"risk_tier": "L1", "risk_drivers": [], "findings": [],
                     "scores": {}, "rationale": "ok"},
        repository="o/r",
        commit_sha="merge-sha",
        **kwargs,
    )


def _approval_events(bundle):
    return [e for e in bundle["events"] if e["event_type"] == "approval_granted"]


def test_bundle_seals_the_approval_and_the_status():
    approval = {"login": "alice", "review_id": 55, "commit_sha": HEAD,
                "approved_at": T0.isoformat()}
    bundle = _bundle(approvals=[approval], human_review={"status": "recorded", "analyzed_head": HEAD})

    event = _approval_events(bundle)[0]
    assert event["actor"] == "alice"
    assert event["data"]["review_id"] == 55
    assert event["data"]["approved_at"] == T0.isoformat()
    assert event["data"]["commit_sha"] == HEAD
    assert bundle["human_review"] == {"status": "recorded", "analyzed_head": HEAD,
                                       "approvers": ["alice"]}

    expected = BundleGenerator._compute_bundle_hash(bundle)
    assert bundle["bundle_hash"] == expected
    bundle["human_review"]["approvers"] = ["mallory"]
    assert BundleGenerator._compute_bundle_hash(bundle) != expected


def test_old_callers_see_no_change():
    bundle = _bundle(approvers=["admin-user"])
    assert [e["actor"] for e in _approval_events(bundle)] == ["admin-user"]
    assert set(_approval_events(bundle)[0]["data"]) == {"risk_tier_at_approval", "commit_sha"}
    assert "human_review" not in bundle
    assert "human_review" not in _bundle()
    assert _approval_events(_bundle()) == []


def _run_main(event, reviews, env_extra=None, base_ref_env=None, auto_merge_spy=None, prs=None):
    """Run main() with a real event file; return create_bundle kwargs and base ref."""
    StubAnalyzer, StubClassifier, packet, raw_diff = _make_stubs()
    pii_client = _make_pii_client(raw_diff)
    seen = {}

    def _create_bundle(**kwargs):
        seen.update(kwargs)
        seen["base_ref"] = os.environ.get("GITHUB_BASE_REF")
        return {"bundle_id": "b", "analysis_snapshot": {}}

    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        event_path = workspace / "event.json"
        event_path.write_text(json.dumps(event), encoding="utf-8")
        gh = MagicMock()
        if prs:
            gh.get_repo.return_value.get_pull.side_effect = prs
        else:
            gh.get_repo.return_value.get_pull.return_value = _pr(reviews)
        env = _make_env(workspace, event_path, INPUT_GENERATE_BUNDLE="true",
                        **(env_extra or {}))
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("GITHUB_BASE_REF", None)
            if base_ref_env:
                os.environ["GITHUB_BASE_REF"] = base_ref_env
            with patch("entrypoint.Github", return_value=gh), \
                 patch("entrypoint.fetch_pr_diff", return_value=raw_diff), \
                 patch("entrypoint.DiffAnalyzer", StubAnalyzer), \
                 patch("entrypoint.RiskClassifier", StubClassifier), \
                 patch("entrypoint.PIIShieldClient", return_value=pii_client), \
                 patch("entrypoint.DecisionEngine") as engine, \
                 patch("entrypoint.render_decision_card", return_value="card"), \
                 patch("entrypoint._governing_rubric_path", return_value=None), \
                 patch("entrypoint._base_ref_config_packs", return_value=[]), \
                 patch("entrypoint.build_governance_record", return_value={}), \
                 patch("entrypoint._auto_merge", auto_merge_spy or MagicMock()), \
                 patch("requests.get", return_value=SimpleNamespace(ok=True, text=raw_diff)), \
                 patch("entrypoint.BundleGenerator") as generator:
                engine.return_value.decide.return_value = packet
                generator.return_value.create_bundle.side_effect = _create_bundle
                with pytest.raises(SystemExit):
                    main()
    return seen


REVIEW_EVENT = {"pull_request": {"number": 7, "base": {"ref": "release/1.x"}}}
SUBMITTED = {"pull_request": {"number": 7, "base": {"ref": "main"},
                              "head": {"sha": HEAD}},
             "review": {"id": 901, "state": "approved"}}
REVIEW_RUN = {"GITHUB_EVENT_NAME": "pull_request_review",
              "GITHUB_RUN_ID": "77", "GITHUB_RUN_ATTEMPT": "2"}


def test_main_passes_real_approvals_into_the_bundle():
    seen = _run_main(REVIEW_EVENT, [_review("alice", "APPROVED", review_id=55)])
    assert [a["login"] for a in seen["approvals"]] == ["alice"]
    assert seen["human_review"] == {"status": "recorded", "analyzed_head": HEAD}


def test_a_new_approval_gets_its_own_bundle_id_but_no_approval_keeps_the_old_one():
    with_approval = _run_main(REVIEW_EVENT, [_review("alice", "APPROVED", review_id=55)])
    without = _run_main(REVIEW_EVENT, [])
    assert with_approval["id_nonce"] == "approvals:55"
    assert without["id_nonce"] == ""


def test_approval_nonce_is_added_to_a_configured_nonce():
    seen = _run_main(REVIEW_EVENT, [_review("alice", "APPROVED", review_id=55)],
                     env_extra={"GUARDSPINE_BUNDLE_NONCE": "run9"})
    assert seen["id_nonce"] == "run9/approvals:55"


def test_review_event_recovers_the_base_ref_for_the_trust_boundary():
    assert _run_main(REVIEW_EVENT, [])["base_ref"] == "release/1.x"


def test_runner_supplied_base_ref_is_never_overridden_by_the_event():
    assert _run_main(REVIEW_EVENT, [], base_ref_env="main")["base_ref"] == "main"


def test_event_without_a_base_ref_leaves_it_unset():
    assert _run_main({"pull_request": {"number": 7}}, [])["base_ref"] is None


def test_head_moving_during_the_run_records_nothing(capsys):
    pr = _pr([_review("alice", "APPROVED", review_id=55)])
    pr.head = SimpleNamespace(sha="pushed-during-run", ref="feature")
    assert _collect(pr) == ([], "unavailable")
    assert "head moved" in capsys.readouterr().out


def test_a_push_during_a_pr_run_still_merges_only_the_analyzed_head():
    """The real merge helper must not pick up a commit nobody analyzed."""
    analyzed = _pr([])
    analyzed.state, analyzed.mergeable = "open", True
    analyzed.merge.return_value = SimpleNamespace(merged=True, sha="merged-sha", message="")
    pushed = _pr([])
    pushed.head = SimpleNamespace(sha="pushed-during-run", ref="feature")
    seen = _run_main({"pull_request": {"number": 7}}, [],
                     env_extra={"INPUT_AUTO_MERGE": "true"},
                     auto_merge_spy=_auto_merge, prs=[analyzed, pushed, pushed])
    assert seen["human_review"]["status"] == "unavailable"
    assert analyzed.merge.call_args.kwargs["sha"] == HEAD
    pushed.merge.assert_not_called()


def test_approval_is_bound_to_the_event_head_not_the_live_pr():
    event = {"pull_request": {"number": 7, "base": {"ref": "main"},
                              "head": {"sha": "event-head-older"}}}
    seen = _run_main(event, [_review("alice", "APPROVED")])
    assert seen["approvals"] == []
    assert seen["human_review"] == {"status": "unavailable", "analyzed_head": "event-head-older"}


def test_review_run_gets_its_own_bundle_id_even_with_no_approvals():
    seen = _run_main(SUBMITTED, [], env_extra=REVIEW_RUN)
    assert seen["id_nonce"] == "review:901:77:2"
    seen = _run_main(SUBMITTED, [_review("alice", "APPROVED", review_id=55)],
                     env_extra=REVIEW_RUN)
    assert seen["id_nonce"] == "review:901:77:2/approvals:55"
    retry = _run_main(SUBMITTED, [], env_extra={**REVIEW_RUN, "GITHUB_RUN_ATTEMPT": "3"})
    assert retry["id_nonce"] == "review:901:77:3"


def test_review_run_never_auto_merges_but_a_pr_run_still_does():
    env = {"INPUT_AUTO_MERGE": "true"}
    spy = MagicMock()
    _run_main(SUBMITTED, [], env_extra={**env, **REVIEW_RUN}, auto_merge_spy=spy)
    spy.assert_not_called()
    _run_main({"pull_request": {"number": 7}}, [], env_extra=env, auto_merge_spy=spy)
    spy.assert_called_once()


def test_review_run_without_a_base_ref_stops_before_any_policy_is_read():
    # _run_main swallows the SystemExit; nothing recorded means it stopped early.
    assert _run_main({"pull_request": {"number": 7}, "review": {"id": 1}}, [],
                     env_extra=REVIEW_RUN) == {}


def test_real_resolver_refuses_a_pr_supplied_rubric_on_a_review_run():
    """No mock of the resolver: the PR's own file must not become the policy."""
    StubAnalyzer, StubClassifier, _packet, _raw = _make_stubs()
    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        (workspace / "weak-policy.yaml").write_text("rules: []\n", encoding="utf-8")
        event_path = workspace / "event.json"
        event_path.write_text(json.dumps(SUBMITTED), encoding="utf-8")
        env = _make_env(workspace, event_path, INPUT_RUBRIC="weak-policy.yaml", **REVIEW_RUN)
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("GITHUB_BASE_REF", None)
            with patch("entrypoint.RiskClassifier", StubClassifier), \
                 patch("entrypoint.Github") as gh:
                with pytest.raises(RubricUnavailableError):
                    main()
            gh.assert_not_called()


def test_stripping_the_seal_from_a_bundle_with_human_review_is_rejected():
    bundle = _bundle(approvals=[], human_review={"status": "none"})
    assert verify_bundle_chain(bundle)[0]

    forged = copy.deepcopy(bundle)
    forged["human_review"]["approvers"] = ["mallory"]
    assert not verify_bundle_chain(forged)[0]

    # Reduce it to an event-only legacy bundle, the shape that skips the seal,
    # keeping only a forged human_review.
    downgraded = {k: v for k, v in bundle.items() if k not in (
        "items", "immutability_proof", "summary", "analysis_snapshot", "context",
        "sanitization", "bundle_hash", "version", "guardspine_spec_version",
    )}
    downgraded["human_review"] = {"status": "recorded", "approvers": ["mallory"]}
    ok, reason = verify_bundle_chain(downgraded)
    assert not ok and "downgrade" in reason


@pytest.mark.xfail(strict=True, reason=(
    "Known defect, also on main without approvals: sanitizing a finished bundle "
    "rewrites sealed fields, and re-sealing doesn't rebuild the chain. Needs "
    "sanitizing before the bundle is built, as a separate change."
))
def test_real_pii_engine_leaves_a_sealed_approval_verifiable():
    client = PIIShieldClient(enabled=True, mode="remote")
    approval = {"login": "alice", "review_id": 55, "commit_sha": "a" * 40,
                "approved_at": "2026-11-06T12:00:00+00:00"}
    bundle = _bundle(approvals=[approval], human_review={"status": "recorded"})
    sanitized, _result = client.sanitize_json_document(bundle, purpose="evidence_bundle")
    event = _approval_events(sanitized)[0]
    assert event["data"] == _approval_events(bundle)[0]["data"]
    assert event["actor"] == "alice"
    assert sanitized["human_review"]["approvers"] == ["alice"]
    BundleGenerator().seal_bundle(sanitized)
    assert verify_bundle_chain(sanitized)[0]


def test_force_push_away_and_back_records_nothing(capsys):
    """Analyzed B while the head went A, B, A: the approval of A isn't of that diff."""
    pr = _pr([_review("alice", "APPROVED", review_id=55)])
    assert _collect(pr, analyzed_diff="diff of B", commit_diff="diff of A") == ([], "unavailable")
    assert "doesn't match" in capsys.readouterr().out
    assert _collect.urls == [f"https://api.github.test/repos/o/r/compare/base-sha...{HEAD}"]


def test_matching_diff_is_recorded_and_no_approvals_skips_the_extra_request():
    approved = _pr([_review("alice", "APPROVED", review_id=55)])
    assert _collect(approved)[1] == "recorded"
    assert _collect(_pr([])) == ([], "none")
    assert _collect.urls == []


def test_commit_diff_that_cannot_be_fetched_is_unavailable():
    pr = _pr([_review("alice", "APPROVED", review_id=55)])
    repo = MagicMock()
    repo.get_pull.return_value = pr
    too_large = SimpleNamespace(ok=False, text="")
    with patch("requests.get", return_value=too_large):
        assert collect_human_approvals(repo, 7, HEAD, DIFF) == ([], "unavailable")
    with patch("requests.get", side_effect=OSError("network detail")):
        assert collect_human_approvals(repo, 7, HEAD, DIFF) == ([], "unavailable")


def test_real_pii_engine_keeps_a_hyphenated_approver_login():
    client = PIIShieldClient(enabled=True, mode="remote")
    approval = {"login": "david-youssef", "review_id": 55, "commit_sha": "a" * 40,
                "approved_at": "2026-11-06T12:00:00+00:00"}
    bundle = _bundle(approvals=[approval], human_review={"status": "recorded"})
    sanitized, _result = client.sanitize_json_document(bundle, purpose="evidence_bundle")
    _restore_approval_records(sanitized, bundle)
    assert _approval_events(sanitized)[0] == _approval_events(bundle)[0]
    assert sanitized["human_review"]["approvers"] == ["david-youssef"]
    items = [i for i in sanitized["items"]
             if i.get("content", {}).get("event_type") == "approval_granted"]
    assert items[0]["content"]["actor"] == "david-youssef"


def test_main_restores_approval_records_after_sanitizing():
    with patch("entrypoint._restore_approval_records") as restore:
        _run_main(SUBMITTED, [], env_extra=REVIEW_RUN)
    restore.assert_called_once()


def test_push_while_reviews_are_being_read_records_nothing(capsys):
    """The head was right when the reviews were read and moved before sealing."""
    before = _pr([_review("alice", "APPROVED", review_id=55)])
    after = _pr([])
    after.head = SimpleNamespace(sha="pushed-during-run", ref="feature")
    repo = MagicMock()
    repo.get_pull.side_effect = [before, after]
    with patch("requests.get", return_value=SimpleNamespace(ok=True, text=DIFF)):
        assert collect_human_approvals(repo, 7, HEAD, DIFF) == ([], "unavailable")
    assert "head moved" in capsys.readouterr().out
