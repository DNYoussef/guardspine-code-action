"""Summary ordering must not mutate sealed history or omit the bundle stage."""
import copy
import json
import os
from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest
from guardspine_kernel.verify import verify_bundle as verify_item_proof

from entrypoint import _init_sanitization_summary, _record_sanitization_stage, main
from src.bundle_generator import verify_bundle_chain
from test_antiforgery import _gen_key, _stub_pr
from test_entrypoint_pii_shield import _make_env, _make_pii_client, _make_stubs


def test_recording_stage_does_not_mutate_previous_snapshot():
    result = _make_pii_client('safe').sanitize_diff.return_value
    previous = _record_sanitization_stage(
        _init_sanitization_summary(result, 'sha256:00000000'), 'ai_prompt', result,
    )
    frozen = copy.deepcopy(previous)
    following = _record_sanitization_stage(
        previous, 'evidence_bundle', replace(result, changed=True, redaction_count=1,
                                           redactions_by_type={'email': 1}),
    )
    assert previous == frozen
    assert following['applied_to'] == ['ai_prompt', 'evidence_bundle']
    assert following['redaction_count'] == 1
    assert following['redactions_by_type'] == {'email': 1}


@pytest.mark.parametrize('changed, mask_fingerprint', [(False, False), (True, False), (True, True)])
def test_saved_signed_bundle_has_current_summary_and_immutable_history(tmp_path, changed, mask_fingerprint):
    analyzer, classifier, packet, raw_diff = _make_stubs()
    packet.effective_decision = 'merge'
    client = _make_pii_client(raw_diff)
    result = client.sanitize_diff.return_value
    calls = []

    def sanitize(document, purpose):
        assert purpose == 'evidence_bundle'
        calls.append(purpose)
        # The unchanged adapter returns the same object, not a deep copy.
        output = json.loads(json.dumps(document, default=str)) if changed else document
        if changed:
            # This leaf changes only an unhashed summary field. Redacting event
            # contents is a separate known-open production integrity blocker.
            output['summary']['rationale'] = '[HIDDEN:test]'
            if mask_fingerprint:
                output['sanitization']['salt_fingerprint'] = '[HIDDEN:test]'
                output['analysis_snapshot']['sanitization']['salt_fingerprint'] = '[HIDDEN:test]'
        return output, replace(result, changed=changed, redaction_count=int(changed),
                               redactions_by_type={'email': 1} if changed else {})

    client.sanitize_json_document.side_effect = sanitize
    _, pem, fingerprint = _gen_key()
    event_path = tmp_path / 'event.json'
    event_path.write_text(json.dumps({'pull_request': {'number': 7}}), encoding='ascii')
    gh = MagicMock()
    gh.get_repo.return_value.get_pull.return_value = _stub_pr()
    env = _make_env(tmp_path, event_path, INPUT_GENERATE_BUNDLE='true',
                    INPUT_PII_SHIELD_SANITIZE_BUNDLE='true', INPUT_ATTESTATION_KEY=pem)
    if mask_fingerprint:
        env['INPUT_PII_SHIELD_SALT_FINGERPRINT'] = 'alice@example.com'
    with patch.dict(os.environ, env, clear=True), \
         patch('entrypoint.Github', return_value=gh), \
         patch('entrypoint.fetch_pr_diff', return_value=raw_diff), \
         patch('entrypoint.DiffAnalyzer', analyzer), \
         patch('entrypoint.RiskClassifier', classifier), \
         patch('entrypoint.PIIShieldClient', return_value=client), \
         patch('entrypoint.DecisionEngine') as engine, \
         patch('entrypoint.render_decision_card', return_value='card'):
        engine.return_value.decide.return_value = packet
        with pytest.raises(SystemExit) as exited:
            main()
    assert exited.value.code == 0
    assert calls == ['evidence_bundle']
    paths = list(tmp_path.rglob('bundle-pr7-*.json'))
    assert len(paths) == 1
    bundle = json.loads(paths[0].read_text(encoding='utf-8'))
    valid, message = verify_bundle_chain(bundle, trusted_fingerprints={fingerprint},
                                         require_signature=True)
    assert valid, message
    summary = bundle['sanitization']
    if mask_fingerprint:
        assert summary['salt_fingerprint'] == '[HIDDEN:test]'
    assert summary == bundle['analysis_snapshot']['sanitization']
    assert summary['applied_to'] == ['ai_prompt', 'evidence_bundle']
    assert summary['redaction_count'] == int(changed)
    historical = bundle['events'][1]['data']['sanitization']
    assert historical['applied_to'] == ['ai_prompt']
    assert historical['redaction_count'] == 0
    assert bundle['items'][1]['content']['data']['sanitization'] == historical
    # Kernel checks the item proof; the legacy verifier above checks the trusted
    # signature and event chain. Neither is substituted for the other.
    proof = {**bundle, 'signatures': []}
    proof_result = verify_item_proof(proof)
    assert proof_result['valid'], proof_result['errors']
    tampered = copy.deepcopy(proof)
    tampered['items'][1]['content']['data']['sanitization']['applied_to'].append('sarif')
    assert not verify_item_proof(tampered)['valid']
    # The same verifier must reject a modified persisted summary.
    bundle['sanitization']['redaction_count'] += 1
    assert not verify_bundle_chain(bundle, trusted_fingerprints={fingerprint},
                                   require_signature=True)[0]
