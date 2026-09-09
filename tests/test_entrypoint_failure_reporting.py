"""A failed scan must not become a clean notice or successful attestation."""
import copy
import json
import os
from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

from entrypoint import _init_sanitization_summary, _record_sanitization_stage, _report_pii_failure, main
from src.pii_shield import PIIShieldClient, PIIShieldError
from test_antiforgery import _stub_pr
from test_entrypoint_pii_shield import _make_env, _make_pii_client, _make_stubs


SECRET = 'REPORTING_PRIVATE_SENTINEL_alice@example.com'
STAGES = ('ai_prompt', 'pr_comment', 'evidence_bundle', 'sarif')


def assert_private(output):
    assert SECRET.lower() not in output.lower()


def test_privacy_oracle_rejects_a_leaked_exception():
    with pytest.raises(AssertionError):
        assert_private('::warning::' + str(TypeError(SECRET)))


def test_failure_label_is_bounded(capsys):
    _report_pii_failure(SECRET, stopped=True)
    output = capsys.readouterr().out
    assert_private(output)
    assert output == '::error::PII-Shield unknown failed; processing stopped\n'


@pytest.mark.parametrize('outcome', ['passthrough', 'disabled', 'exception'])
def test_real_adapter_non_scan_binding_and_frozen_history(outcome):
    client = PIIShieldClient(enabled=outcome != 'disabled', mode='auto', fail_closed=False)
    with patch.object(client, '_redact', side_effect=RuntimeError(SECRET)):
        result = client.sanitize_diff('safe')
    assert result.provider == ('none' if outcome == 'disabled' else 'passthrough')
    previous = _init_sanitization_summary(result, 'sha256:00000000')
    frozen = copy.deepcopy(previous)
    following = _record_sanitization_stage(
        previous, 'ai_prompt', None if outcome == 'exception' else result,
    )
    assert previous == frozen
    assert following['applied_to'] == []
    assert following['redaction_count'] == 0
    assert following['redactions_by_type'] == {}
    assert following['status'] == ('none' if outcome == 'disabled' else 'error')
    assert following['input_hash'] == following['output_hash']
    assert following['engine_version'] == 'unknown'
    frozen_following = copy.deepcopy(following)
    success = replace(result, mode='wasm-local', provider='pii-shield-wasi',
                      changed=True, redaction_count=1, redactions_by_type={'email': 1})
    last = _record_sanitization_stage(following, 'evidence_bundle', success)
    assert following == frozen_following
    assert last['applied_to'] == ['evidence_bundle']
    assert last['redaction_count'] == 1
    assert last['redactions_by_type'] == {'email': 1}
    assert last['status'] == ('sanitized' if outcome == 'disabled' else 'error')


@pytest.mark.parametrize('stage', STAGES)
@pytest.mark.parametrize('outcome,fail_closed', [
    ('generic', False), ('generic', True), ('fatal', False), ('fatal', True),
    ('passthrough', False), ('clean', False), ('changed', False),
])
def test_main_failure_reporting_and_publication(tmp_path, capsys, stage, outcome, fail_closed):
    analyzer, base_classifier, packet, raw_diff = _make_stubs()
    packet.effective_decision = 'merge'

    class Classifier(base_classifier):
        def classify(self, analysis):
            result = super().classify(analysis)
            result['findings'] = [{'id': 'reporting-control', 'message': 'safe',
                                   'severity': 'low', 'file': 'app.py', 'line': 1}]
            return result

    client = _make_pii_client(raw_diff)
    clean = client.sanitize_diff.return_value
    reached = []

    def scan(text, current):
        reached.append(current)
        if current == stage:
            if outcome == 'generic':
                raise TypeError(SECRET)
            if outcome == 'fatal':
                raise PIIShieldError(SECRET)
            if outcome == 'passthrough':
                real = PIIShieldClient(enabled=True, mode='auto', fail_closed=False)
                with patch.object(real, '_redact', side_effect=RuntimeError(SECRET)):
                    return real.sanitize_text(text)
        changed = current == stage and outcome == 'changed'
        output = 'redacted-card' if changed and current == 'pr_comment' else text
        return replace(clean, sanitized_text=output, changed=changed,
                       redaction_count=int(changed),
                       redactions_by_type={'email': 1} if changed else {})

    client.sanitize_diff.side_effect = lambda text: scan(text, 'ai_prompt')
    client.sanitize_text.side_effect = lambda text, **kw: scan(text, kw['purpose'])
    client.sanitize_json_document.side_effect = lambda document, purpose, **options: (
        document, scan(json.dumps(document, default=str), purpose),
    )
    event = tmp_path / 'event.json'
    event.write_text(json.dumps({'pull_request': {'number': 7}}), encoding='ascii')
    env = _make_env(tmp_path, event, INPUT_POST_COMMENT='true',
                    INPUT_GENERATE_BUNDLE='true', INPUT_UPLOAD_SARIF='true',
                    INPUT_PII_SHIELD_FAIL_CLOSED=str(fail_closed).lower())
    gh = MagicMock()
    gh.get_repo.return_value.get_pull.return_value = _stub_pr()
    with patch.dict(os.environ, env, clear=True), \
         patch('entrypoint.Github', return_value=gh), \
         patch('entrypoint.fetch_pr_diff', return_value=raw_diff), \
         patch('entrypoint.DiffAnalyzer', analyzer), \
         patch('entrypoint.RiskClassifier', Classifier), \
         patch('entrypoint.PIIShieldClient', return_value=client), \
         patch('entrypoint.PRCommenter') as commenter, \
         patch('entrypoint.DecisionEngine') as engine, \
         patch('entrypoint.render_decision_card', return_value='original-card'):
        engine.return_value.decide.return_value = packet
        with pytest.raises(SystemExit) as exited:
            main()
    output = capsys.readouterr()
    log = output.out + output.err
    # A setup failure cannot impersonate reaching the intended error boundary.
    assert stage in reached
    fatal = outcome == 'fatal' or (outcome == 'generic' and (stage == 'ai_prompt' or fail_closed))
    assert exited.value.code == int(fatal)
    assert reached == list(STAGES[:STAGES.index(stage) + 1] if fatal else STAGES)
    assert_private(log)
    failed = outcome in {'generic', 'fatal', 'passthrough'}
    if failed:
        consequence = 'processing stopped' if fatal else 'continuing with unsanitized content'
        assert f'PII-Shield {stage} failed; {consequence}' in log
    else:
        assert f'PII-Shield {stage} failed' not in log
    if stage == 'ai_prompt':
        assert ('no redactable content detected' in log) == (outcome == 'clean')
    paths = list(tmp_path.rglob('bundle-pr7-*.json'))
    bundle_expected = not fatal or stage == 'sarif'
    assert len(paths) == int(bundle_expected)
    assert (tmp_path / 'guardspine-results.sarif').exists() == (not fatal)
    posted = commenter.return_value.post_decision_card
    assert posted.call_count == int(not fatal or stage in {'evidence_bundle', 'sarif'})
    if posted.called:
        expected_body = 'redacted-card' if stage == 'pr_comment' and outcome == 'changed' else 'original-card'
        assert posted.call_args.args[0] == expected_body
    if paths:
        bundle = json.loads(paths[0].read_text(encoding='utf-8'))
        summary = bundle['sanitization']
        persisted_failure = failed and stage != 'sarif'
        assert summary['status'] == ('error' if persisted_failure else
                                     'sanitized' if outcome == 'changed' and stage != 'sarif' else 'none')
        assert summary['applied_to'] == [s for s in STAGES[:3]
                                         if not (persisted_failure and s == stage)]
        assert summary == bundle['analysis_snapshot']['sanitization']
        assert summary['redaction_count'] == int(outcome == 'changed' and stage != 'sarif')


@pytest.mark.parametrize('mode', [SECRET, 'local', ' Local '])
def test_configuration_failure_is_fixed_and_has_remedy(tmp_path, capsys, mode):
    event = tmp_path / 'event.json'
    event.write_text(json.dumps({'pull_request': {'number': 7}}), encoding='ascii')
    env = _make_env(tmp_path, event, INPUT_PII_SHIELD_MODE=mode)
    gh = MagicMock()
    gh.get_repo.return_value.get_pull.return_value = _stub_pr()
    with patch.dict(os.environ, env, clear=True), \
         patch('entrypoint.Github', return_value=gh), \
         patch('entrypoint.fetch_pr_diff', return_value='safe'):
        with pytest.raises(SystemExit) as exited:
            main()
    assert exited.value.code == 1
    output = capsys.readouterr()
    log = output.out + output.err
    assert_private(log)
    boundary = 'ai_prompt' if mode.strip().lower() == 'local' else 'setup'
    assert f'::error::PII-Shield {boundary} failed; processing stopped' in log
    assert "Use pii_shield_mode='auto'" in log
