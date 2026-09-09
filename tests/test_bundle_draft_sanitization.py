"""Producer redaction must precede proofs and cannot rewrite evidence structure."""
import copy
import json
import os
import sys
from pathlib import Path
from contextlib import nullcontext
from unittest.mock import MagicMock, patch

import pytest
from guardspine_kernel.verify import verify_bundle as verify_item_proof

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from entrypoint import main
from src.bundle_generator import BundleGenerator, BundleEvent, InvalidBundleDraft, verify_bundle_chain
from src.pii_shield import PIIShieldClient, PIIShieldError
from test_antiforgery import _gen_key, _stub_pr
from test_entrypoint_pii_shield import _make_env, _make_pii_client, _make_stubs


SECRET = 'alice@example.com'


def assert_no_secret(bundle):
    assert SECRET not in json.dumps(bundle)


def test_absence_oracle_has_positive_control():
    with pytest.raises(AssertionError):
        assert_no_secret({'event': SECRET})


def assert_proofs(bundle, fingerprint):
    assert '_labels' not in bundle
    valid, message = verify_bundle_chain(bundle, trusted_fingerprints={fingerprint},
                                         require_signature=True)
    assert valid, message
    result = verify_item_proof({**bundle, 'signatures': []})
    assert result['valid'], result['errors']


@pytest.mark.parametrize('real_engine', [True, False, 'producer_input', 'accounting', 'structure_identity', 'invalid_draft'])
def test_real_engine_saved_signed_event_is_redacted_before_proofs(tmp_path, capsys, real_engine):
    analyzer, classifier, packet, raw_diff = _make_stubs()
    packet.effective_decision = 'merge'
    client = _make_pii_client(raw_diff)
    real = PIIShieldClient(enabled=True, mode='auto', fail_closed=True)
    def redact(document, purpose, **options):
        if real_engine:
            return real.sanitize_json_document(document, purpose, **options)
        from dataclasses import replace
        text = json.dumps(document, default=str).replace(SECRET, '[HIDDEN:test]')
        return json.loads(text), replace(client.sanitize_diff.return_value,
                                        changed=True, redaction_count=1)
    client.sanitize_json_document.side_effect = redact
    pr = _stub_pr()
    pr.title = 'Contact ' + SECRET
    gh = MagicMock()
    gh.get_repo.return_value.get_pull.return_value = pr
    event = tmp_path / 'event.json'
    event.write_text(json.dumps({'pull_request': {'number': 7}}), encoding='ascii')
    _, pem, fingerprint = _gen_key()
    env = _make_env(tmp_path, event, INPUT_GENERATE_BUNDLE='true',
                    INPUT_PII_SHIELD_SANITIZE_BUNDLE='true', INPUT_ATTESTATION_KEY=pem)
    # Clear application credentials, not Windows' architecture/loader identity.
    for key in ('SYSTEMROOT', 'WINDIR', 'PROCESSOR_ARCHITECTURE',
                'PROCESSOR_IDENTIFIER', 'PROCESSOR_ARCHITEW6432'):
        if key in os.environ:
            env[key] = os.environ[key]
    rejection = {'producer_input': 'Invalid producer bundle draft',
                 'accounting': 'Invalid sanitized bundle accounting',
                 'structure_identity': 'Invalid sanitized bundle draft',
                 'invalid_draft': SECRET}.get(real_engine)
    with patch.dict(os.environ, env, clear=True), \
         patch('entrypoint.Github', return_value=gh), \
         patch('entrypoint.fetch_pr_diff', return_value=raw_diff), \
         patch('entrypoint.DiffAnalyzer', analyzer), \
         patch('entrypoint.RiskClassifier', classifier), \
         patch('entrypoint.PIIShieldClient', return_value=client), \
         patch('entrypoint.DecisionEngine') as engine, \
         (patch('entrypoint.BundleGenerator.create_bundle', side_effect=InvalidBundleDraft(rejection))
          if rejection else nullcontext()):
        engine.return_value.decide.return_value = packet
        with pytest.raises(SystemExit) as exited:
            main()
    if rejection:
        assert exited.value.code == 1
        output = capsys.readouterr().out
        assert f'::error::Evidence bundle rejected ({real_engine}); processing stopped' in output
        assert SECRET not in output
        assert not list(tmp_path.rglob('bundle-pr7-*.json'))
        return
    assert exited.value.code == 0
    paths = list(tmp_path.rglob('bundle-pr7-*.json'))
    assert len(paths) == 1
    bundle = json.loads(paths[0].read_text(encoding='utf-8'))
    assert_no_secret(bundle)
    assert '[HIDDEN' in bundle['events'][0]['data']['title']
    assert_proofs(bundle, fingerprint)


def inputs():
    return dict(pr=_stub_pr(), analysis={'files_changed': 2, 'lines_added': 3,
                'lines_removed': 0, 'diff_hash': 'abc', 'ai_summary': {'score': -0.0}},
                risk_result={'risk_tier': 'L2', 'scores': {'score': 2.5},
                             'findings': [{'message': 'contact ' + SECRET}]},
                repository='owner/repo', commit_sha='deadbeef')


@pytest.mark.parametrize('path,value', [
    (('items',), []), (('events',), []), (('context',), []),
    (('context', 'pr_number'), True), (('context', 'pr_number'), 8),
    (('context', 'pr_number'), 7.0), (('context', 'commit_sha'), 'other'),
    (('context', 'repository'), 'other/repo'), (('bundle_id',), 'other'),
    (('version',), 'other'), (('guardspine_spec_version',), 'other'),
    (('created_at',), 'other'), (('events', 0, 'event_type'), 'other'),
    (('events', 0, 'timestamp'), 'other'),
    (('events', 0, 'data', 'head_sha'), 'other'),
    (('summary', 'risk_tier'), 'L0'), (('summary', 'decision'), 'reject'),
    (('analysis_snapshot', 'ai_summary', 'score'), 0.0),
    (('events', 2, 'data', 'scores', 'score'), 2.6),
])
def test_invalid_draft_never_hashes_signs_or_records(path, value):
    def corrupt(draft):
        target = draft
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        return draft, object()

    generator = BundleGenerator()
    recorder = MagicMock()
    with patch.object(BundleEvent, 'compute_hash') as hash_event, \
         patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(ValueError, match='Invalid sanitized bundle draft'):
            generator.create_bundle(**inputs(), sanitize_draft=corrupt,
                                    record_sanitization=recorder)
    hash_event.assert_not_called()
    seal.assert_not_called()
    recorder.assert_not_called()


def test_valid_string_redaction_detaches_inputs_and_survives_both_verifiers():
    args = inputs()
    frozen = copy.deepcopy(args['risk_result'])
    _, pem, fingerprint = _gen_key()

    def sanitize(draft):
        assert not {'items', 'hash_chain', 'bundle_hash', 'signatures',
                    'immutability_proof'} & draft.keys()
        assert all('hash' not in event for event in draft['events'])
        draft['summary']['findings'][0]['message'] = '[HIDDEN:test]'
        draft['events'][0]['data']['title'] = '[HIDDEN:test]'
        return draft, None

    generator = BundleGenerator()
    with patch.object(generator, '_sign_bundle', wraps=generator._sign_bundle) as sign:
        bundle = generator.create_bundle(**args, attestation_key=pem,
                                         sanitize_draft=sanitize)
    assert sign.call_count == 1
    assert args['risk_result'] == frozen
    assert_no_secret(bundle)
    assert_proofs(bundle, fingerprint)
    assert bundle['events'][2]['data']['scores'] == {'score': 2.5}
    for lane in ('events', 'items'):
        damaged = json.loads(json.dumps(bundle))
        content = damaged[lane][0] if lane == 'events' else damaged[lane][0]['content']
        content['data']['title'] = 'tampered'
        generator.seal_bundle(damaged, attestation_key=pem)
        if lane == 'events':
            assert not verify_bundle_chain(damaged)[0]
            assert verify_item_proof({**damaged, 'signatures': []})['valid']
        else:
            assert not verify_item_proof({**damaged, 'signatures': []})['valid']
            assert verify_bundle_chain(damaged)[0]


def test_real_engine_covers_user_fields_without_key_name_exemptions():
    from entrypoint import _init_sanitization_summary
    args = inputs()
    pr = args['pr']
    pr.title = pr.user.login = pr.base.ref = pr.head.ref = SECRET
    args['approvers'] = [SECRET]
    args['commit_sha'] = '3b9574e04fa1dbf3b6d4d2729a10f50bf36f4545'
    args['analysis']['ai_summary'] = {'a_hash': SECRET}
    args['analysis']['model_errors'] = [SECRET]
    args['analysis']['sanitization'] = _init_sanitization_summary(
        _make_pii_client('safe').sanitize_diff.return_value, SECRET)
    args['analysis']['multi_model_review'] = {'reviews': [
        {'model_name': 'test', 'provider': 'test', 'model_id': 'test', 'concerns': [SECRET],
         'prompt_hash': 'a' * 64, 'response_hash': 'b' * 64}]}
    args['governance'] = {'skipped_packs': {'test': SECRET}, 'rubric_input': 'default'}
    args['risk_result']['rationale'] = SECRET
    frozen = copy.deepcopy(args['analysis'])
    client = PIIShieldClient(enabled=True, mode='auto', fail_closed=True)
    captured = []

    def scan(draft):
        captured.append(copy.deepcopy(draft))
        return client.sanitize_json_document(draft, 'evidence_bundle', preserve_hash_fields=False)

    _, pem, fingerprint = _gen_key()
    bundle = BundleGenerator().create_bundle(**args, attestation_key=pem, sanitize_draft=scan)
    assert args['analysis'] == frozen
    assert len(captured) == 1
    assert 'event_type' not in captured[0]['events'][0]
    assert 'actor' not in captured[0]['events'][1]
    assert captured[0]['events'][0]['actor'] == SECRET
    assert captured[0]['events'][3]['actor'] == SECRET
    assert captured[0]['analysis_snapshot']['ai_summary']['a_hash'] == SECRET
    assert_no_secret(bundle)
    assert_proofs(bundle, fingerprint)
    assert bundle['context']['commit_sha'] == args['commit_sha']
    assert bundle['events'][1]['data']['reviews_sealed'][0]['prompt_hash'] == 'a' * 64
    assert bundle['analysis_snapshot']['multi_model_review']['reviews'][0]['response_hash'] == 'b' * 64
    assert bundle['events'][2]['data']['scores'] == {'score': 2.5}
    assert type(bundle['events'][2]['data']['scores']['score']) is float


@pytest.mark.parametrize('field', ['actor', 'title'])
def test_user_protocol_lookalikes_are_still_scanned(field):
    args = inputs()
    if field == 'actor':
        args['pr'].user.login = 'guardspine-codeguard'
    else:
        args['pr'].title = 'pr_submitted'
    client = PIIShieldClient(enabled=True, mode='auto', fail_closed=True)
    bundle = BundleGenerator().create_bundle(**args, sanitize_draft=lambda draft:
        client.sanitize_json_document(draft, 'evidence_bundle', preserve_hash_fields=False))
    value = bundle['events'][0]['actor'] if field == 'actor' else bundle['events'][0]['data']['title']
    assert '[HIDDEN' in value
    assert bundle['events'][0]['event_type'] == 'pr_submitted'
    assert bundle['events'][1]['actor'] == 'guardspine-codeguard'


@pytest.mark.parametrize('location', ['key', 'identity', 'rubric', 'requested', 'loaded'])
def test_real_pii_in_keys_or_identity_is_refused(location):
    args = inputs()
    if location == 'key':
        args['analysis']['ai_summary'] = {SECRET: 'ordinary'}
    elif location == 'identity':
        args['repository'] = SECRET
    else:
        field = {'rubric': 'rubric_input', 'requested': 'requested_packs', 'loaded': 'loaded_packs'}[location]
        args['governance'] = {field: SECRET if location == 'rubric' else [SECRET]}
    client = PIIShieldClient(enabled=True, mode='auto', fail_closed=True)
    with pytest.raises(ValueError, match='Invalid sanitized bundle draft'):
        BundleGenerator().create_bundle(**args, sanitize_draft=lambda draft:
            client.sanitize_json_document(draft, 'evidence_bundle', preserve_hash_fields=False))


def test_duplicate_json_keys_refused_on_bundle_path_even_fail_open():
    client = PIIShieldClient(enabled=True, mode='auto', fail_closed=False)
    with patch.object(client, '_redact', return_value='{"a": "safe", "a": "other"}'):
        with pytest.raises(PIIShieldError, match='duplicate JSON keys'):
            client.sanitize_json_document({'a': 'safe'}, preserve_hash_fields=False)


def test_default_json_path_keeps_duplicate_key_compatibility():
    client = PIIShieldClient(enabled=True, mode='auto', fail_closed=False)
    with patch.object(client, '_redact', return_value='{"a": "safe", "a": "other"}'):
        result, _ = client.sanitize_json_document({'a': 'safe'})
    assert result == {'a': 'other'}


def test_accounting_extra_fields_cannot_edit_content():
    from entrypoint import _init_sanitization_summary
    args = inputs()
    summary = _init_sanitization_summary(_make_pii_client('safe').sanitize_diff.return_value, 'safe')
    args['analysis']['sanitization'] = summary
    bundle = BundleGenerator().create_bundle(**args, sanitize_draft=lambda draft: (draft, None),
        record_sanitization=lambda _: {**summary, 'salt_fingerprint': SECRET, 'context': SECRET})
    assert bundle['sanitization']['salt_fingerprint'] == 'safe'
    assert bundle['analysis_snapshot']['sanitization']['salt_fingerprint'] == 'safe'
    assert bundle['context']['repository'] == args['repository']
    assert '_labels' not in bundle


def test_labels_signer_identity_mutation_is_refused_before_signing():
    def scan(draft):
        draft['_labels'][-1] = 'differentkey'
        return draft, None
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(ValueError, match='^Invalid sanitized bundle draft$'):
            generator.create_bundle(**inputs(), attestation_key_id='knownkey', sanitize_draft=scan)
    seal.assert_not_called()


@pytest.mark.parametrize('changed', [True, False])
def test_normalized_callback_and_default_types_are_compatible(changed):
    args = inputs()
    args['analysis']['ai_summary'] = {'tuple': ('a', 'b'), 'set': {'c', 'd'}, 'float': 1.0}
    default = BundleGenerator().create_bundle(**args)
    assert type(default['analysis_snapshot']['ai_summary']['tuple']) is tuple
    assert type(default['analysis_snapshot']['ai_summary']['set']) is set

    def scan(draft):
        assert draft['analysis_snapshot']['ai_summary'] == {
            'tuple': ['a', 'b'], 'set': ['c', 'd'], 'float': 1.0}
        return (copy.deepcopy(draft) if changed else draft), None

    bundle = BundleGenerator().create_bundle(**args, sanitize_draft=scan)
    assert verify_bundle_chain(bundle)[0]
    assert type(bundle['analysis_snapshot']['ai_summary']['float']) is float


def test_failed_callback_mutation_is_discarded_and_truthfully_recorded():
    from entrypoint import _init_sanitization_summary, _record_sanitization_stage
    args = inputs()
    clean = _make_pii_client('safe').sanitize_diff.return_value
    summary = _init_sanitization_summary(clean, 'sha256:00000000')
    args['analysis']['sanitization'] = summary
    frozen = copy.deepcopy(args['analysis'])

    def fail(draft):
        draft['events'][0]['data']['title'] = 'CORRUPTED_PARTIAL_RESULT'
        return None, None

    bundle = BundleGenerator().create_bundle(**args, sanitize_draft=fail,
        record_sanitization=lambda result: _record_sanitization_stage(summary, 'evidence_bundle', result))
    assert args['analysis'] == frozen
    assert bundle['events'][0]['data']['title'] == args['pr'].title
    assert bundle['sanitization']['status'] == 'error'
    assert bundle['sanitization']['applied_to'] == []
    assert bundle['events'][1]['data']['sanitization']['status'] == 'none'
    assert verify_bundle_chain(bundle)[0]


@pytest.mark.parametrize('patch_summary', [
    {'redaction_count': True}, {'redaction_count': -1}, {'redaction_count': float('inf')},
    {'status': 'clean'}, {'applied_to': ['unknown']}, {'applied_to': ['ai_prompt', 'ai_prompt']},
    {'redactions_by_type': {'email': -1}}, {'redactions_by_type': {'email': True}},
])
def test_invalid_accounting_is_never_signed(patch_summary):
    from entrypoint import _init_sanitization_summary
    args = inputs()
    summary = _init_sanitization_summary(_make_pii_client('safe').sanitize_diff.return_value, 'safe')
    args['analysis']['sanitization'] = summary
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(ValueError, match='Invalid sanitized bundle accounting'):
            generator.create_bundle(**args, sanitize_draft=lambda draft: (draft, None),
                                    record_sanitization=lambda _: {**summary, **patch_summary})
    seal.assert_not_called()


@pytest.mark.parametrize('key_id', ['knownkey', SECRET])
def test_signer_identity_is_scanned_and_never_changed(key_id):
    args = inputs()
    _, pem, fingerprint = _gen_key()
    client = PIIShieldClient(enabled=True, mode='auto', fail_closed=True)
    call = lambda: BundleGenerator().create_bundle(**args, attestation_key=pem,
        attestation_key_id=key_id, sanitize_draft=lambda draft: client.sanitize_json_document(
            draft, 'evidence_bundle', preserve_hash_fields=False))
    if key_id == SECRET:
        with pytest.raises(ValueError, match='Invalid sanitized bundle draft'):
            call()
    else:
        bundle = call()
        assert bundle['signatures'][0]['public_key_id'] == key_id
        assert '_labels' not in bundle
        assert_proofs(bundle, fingerprint)


@pytest.mark.parametrize('mutator', [
    lambda draft: draft['context'].pop('pr_number'),
    lambda draft: draft['summary']['findings'].append({'message': 'extra'}),
    lambda draft: draft['events'].reverse(),
    lambda draft: draft['events'][0].update(hash='injected'),
    lambda draft: draft['events'][1]['data'].update(diff_hash='forged'),
])
def test_deleted_added_reordered_and_provenance_data_refuses(mutator):
    def scan(draft):
        mutator(draft)
        return draft, None
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(ValueError, match='Invalid sanitized bundle draft'):
            generator.create_bundle(**inputs(), sanitize_draft=scan)
    seal.assert_not_called()


def test_invalid_canonical_input_has_no_content_bearing_error():
    args = inputs()
    args['analysis']['ai_summary'] = {1: 'safe', '1': SECRET}
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(ValueError, match='^Invalid producer bundle draft$') as error:
            generator.create_bundle(**args, sanitize_draft=lambda draft: (draft, None))
    assert SECRET not in str(error.value)
    seal.assert_not_called()


def test_disabled_real_adapter_keeps_explicit_unscanned_behavior():
    args = inputs()
    client = PIIShieldClient(enabled=False, mode='auto', fail_closed=True)
    outcomes = []
    def scan(draft):
        result, outcome = client.sanitize_json_document(draft, preserve_hash_fields=False)
        assert result is draft
        outcomes.append(outcome)
        return result, outcome
    bundle = BundleGenerator().create_bundle(**args, sanitize_draft=scan)
    assert outcomes[0].mode == 'disabled'
    assert bundle['sanitization'] is None
    assert SECRET in bundle['summary']['findings'][0]['message']
    assert verify_bundle_chain(bundle)[0]


def test_user_field_names_do_not_freeze_redactable_values():
    args = inputs()
    args['analysis']['ai_summary'] = {'provider': SECRET, 'model_name': SECRET,
        'decision': SECRET, 'sanitization': {'provider': SECRET}}
    def scan(draft):
        return json.loads(json.dumps(draft).replace(SECRET, '[HIDDEN:test]')), None
    bundle = BundleGenerator().create_bundle(**args, sanitize_draft=scan)
    assert_no_secret(bundle)
    assert bundle['analysis_snapshot']['ai_summary']['provider'] == '[HIDDEN:test]'
    assert '_labels' not in bundle
    assert verify_bundle_chain(bundle)[0]


@pytest.mark.parametrize('review', [{'reviews': {'a': {'message': SECRET}}},
                                  {'reviews': [SECRET]}, {'reviews': SECRET}, SECRET])
def test_malformed_review_refuses_with_fixed_error(review):
    args = inputs()
    args['analysis']['multi_model_review'] = review
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(ValueError, match='^Invalid producer bundle draft$') as error:
            generator.create_bundle(**args, sanitize_draft=lambda draft: (draft, None))
    assert SECRET not in str(error.value)
    seal.assert_not_called()


@pytest.mark.parametrize('reported', ['first', 'uncollected'])
def test_gate_rejects_same_count_wrong_execution_identity(reported):
    import runpy
    import subprocess
    verifier = Path(__file__).resolve().parents[1] / 'docs/operations/bundle-ordering-20260908/verify_bundle_ordering.py'
    def run(command, **kwargs):
        if '--collect-only' in command:
            return subprocess.CompletedProcess(command, 0, 'tests/control.py::first\ntests/control.py::second\n')
        report = Path(next(arg.split('=', 1)[1] for arg in command if arg.startswith('--junitxml=')))
        report.write_text('<testsuite><testcase classname="tests.control" name="first"/>'
                          f'<testcase classname="tests.control" name="{reported}"/></testsuite>', encoding='ascii')
        return subprocess.CompletedProcess(command, 0)
    with patch('subprocess.run', side_effect=run), patch.object(sys, 'argv', [str(verifier)]):
        with pytest.raises(SystemExit) as exited:
            runpy.run_path(str(verifier), run_name='__main__')
    assert exited.value.code != 0


@pytest.mark.parametrize('field', ['rubric_input', 'requested_packs', 'loaded_packs'])
def test_governance_control_identity_cannot_be_rewritten(field):
    args = inputs()
    args['governance'] = {'rubric_input': 'default', 'requested_packs': ['soc2'],
                          'loaded_packs': ['soc2'], 'catalogue_version': '0.2.0'}
    def scan(draft):
        draft['governance'][field] = 'other' if field == 'rubric_input' else ['other']
        return draft, None
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(ValueError, match='^Invalid sanitized bundle draft$'):
            generator.create_bundle(**args, sanitize_draft=scan)
    seal.assert_not_called()


def test_repository_pack_identities_survive_real_engine():
    import yaml
    from src.risk_classifier import RiskClassifier
    from src.bundle_generator import build_governance_record
    config = yaml.safe_load((Path(__file__).resolve().parents[1] / '.guardspine/config.yml').read_text())
    packs = config['rubric_packs']
    assert packs and all(isinstance(pack, str) for pack in packs)
    args = inputs()
    classifier = RiskClassifier(config_packs=packs)
    args['analysis']['files'] = [{'path': 'app.py', 'hunks': [{'lines': [
        {'type': 'add', 'content': 'pickle.loads(payload)', 'line_number': 1}]}]}]
    args['risk_result'] = classifier.classify(args['analysis'])
    fired = [finding for finding in args['risk_result']['findings'] if finding['source_pack'] in packs]
    assert fired
    args['risk_result']['rationale'] += ' Contact ' + SECRET
    args['governance'] = build_governance_record(classifier, classifier.rubric)
    original = copy.deepcopy(args['governance'])
    client = PIIShieldClient(enabled=True, mode='auto', fail_closed=True)
    _, pem, fingerprint = _gen_key()
    bundle = BundleGenerator().create_bundle(**args, attestation_key=pem,
        sanitize_draft=lambda draft: client.sanitize_json_document(draft, preserve_hash_fields=False))
    assert bundle['governance'] == original
    assert [finding['source_pack'] for finding in bundle['summary']['findings']] == [
        finding['source_pack'] for finding in args['risk_result']['findings']]
    assert_no_secret(bundle)
    assert_proofs(bundle, fingerprint)


@pytest.mark.parametrize('path', [
    *(('summary', 'findings', 0, key) for key in ('id', 'rule_id', 'source_pack', 'severity', 'zone', 'control_category')),
    *(('summary', 'risk_drivers', 0, key) for key in ('type', 'rule', 'severity', 'zone', 'tier')),
    ('analysis_snapshot', 'multi_model_review', 'rubric_name'),
    ('analysis_snapshot', 'multi_model_review', 'reviews', 0, 'risk_assessment'),
    ('analysis_snapshot', 'multi_model_review', 'reviews', 0, 'intent'),
    ('analysis_snapshot', 'multi_model_review', 'consensus', 'consensus_risk'),
    ('analysis_snapshot', 'ai_summary', 'intent'),
])
def test_classification_and_attribution_are_not_redactable_prose(path):
    args = inputs()
    args['risk_result']['findings'] = [{'id': 'finding-1', 'rule_id': 'SEC-004',
        'source_pack': 'unknown-pack', 'severity': 'high', 'zone': 'security', 'control_category': 'code'}]
    args['risk_result']['risk_drivers'] = [{'type': 'policy_finding', 'rule': 'SEC-004',
        'severity': 'high', 'zone': 'security', 'tier': 'L2'}]
    args['analysis']['ai_summary']['intent'] = 'feature'
    args['analysis']['multi_model_review'] = {'rubric_name': 'custom.yaml',
        'reviews': [{'risk_assessment': 'comment', 'intent': 'feature'}],
        'consensus': {'consensus_risk': 'comment'}}
    def scan(draft):
        target = draft
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = 'different'
        return draft, None
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal, patch.object(BundleEvent, 'compute_hash') as hash_event:
        with pytest.raises(InvalidBundleDraft, match='^Invalid sanitized bundle draft$'):
            generator.create_bundle(**args, sanitize_draft=scan)
    seal.assert_not_called()
    hash_event.assert_not_called()


@pytest.mark.parametrize('slot', ['source_pack', 'rule_id', 'id'])
def test_unknown_private_finding_identity_is_never_catalogue_exempt(slot):
    args = inputs()
    args['risk_result']['findings'] = [{'source_pack': 'security', 'rule_id': 'SEC-004',
                                      'id': 'RUBRIC-SEC-004', 'message': 'safe'}]
    args['risk_result']['findings'][0][slot] = SECRET
    client = PIIShieldClient(enabled=True, mode='auto', fail_closed=True)
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(InvalidBundleDraft, match='^Invalid sanitized bundle draft$'):
            generator.create_bundle(**args, sanitize_draft=lambda draft:
                client.sanitize_json_document(draft, preserve_hash_fields=False))
    seal.assert_not_called()


def test_catalogue_placeholders_are_private_and_user_lookalikes_still_scan():
    args = inputs()
    args['governance'] = {'requested_packs': ['security', 'unknown-pack'], 'loaded_packs': ['security']}
    args['risk_result']['findings'] = [{'source_pack': 'security', 'rule_id': 'SEC-004',
                                      'id': 'RUBRIC-SEC-004', 'message': 'RUBRIC-SEC-004'}]
    def scan(draft):
        assert draft['governance']['requested_packs'] == [None, 'unknown-pack']
        assert draft['governance']['loaded_packs'] == [None]
        assert draft['summary']['findings'][0] == {'message': 'RUBRIC-SEC-004'}
        draft['summary']['findings'][0]['message'] = '[HIDDEN:test]'
        return draft, None
    bundle = BundleGenerator().create_bundle(**args, sanitize_draft=scan)
    assert bundle['governance'] == args['governance']
    assert bundle['summary']['findings'][0]['id'] == 'RUBRIC-SEC-004'
    assert bundle['summary']['findings'][0]['message'] == '[HIDDEN:test]'
    assert verify_bundle_chain(bundle)[0]


def test_catalogue_failure_is_a_fixed_producer_error():
    from src.risk_classifier import RiskClassifier
    with patch.object(RiskClassifier, 'shipped_rubrics', side_effect=RuntimeError(SECRET)):
        with pytest.raises(InvalidBundleDraft, match='^Invalid producer bundle draft$'):
            BundleGenerator().create_bundle(**inputs(), sanitize_draft=lambda draft: (draft, None))


@pytest.mark.parametrize('lane', ['key', 'value'])
def test_real_engine_detects_nonfirst_array_elements(lane):
    args = inputs()
    args['governance'] = {'skipped_packs': {'test': 'safe'}}
    if lane == 'key':
        args['analysis']['ai_summary'] = {SECRET: 'ordinary'}
    else:
        args['analysis']['model_errors'] = ['safe', SECRET]
    client = PIIShieldClient(enabled=True, mode='auto', fail_closed=True)
    reached = []
    def scan(draft):
        if lane == 'key':
            index = draft['_labels'].index(SECRET)
            assert index > 0
        sanitized, result = client.sanitize_json_document(draft, preserve_hash_fields=False)
        if lane == 'key':
            assert SECRET in sanitized['analysis_snapshot']['ai_summary']
            assert sanitized['_labels'][index] != SECRET
        else:
            assert sanitized['analysis_snapshot']['model_errors'][0] == 'safe'
            assert SECRET not in sanitized['analysis_snapshot']['model_errors'][1]
            assert '[HIDDEN' in sanitized['analysis_snapshot']['model_errors'][1]
        reached.append(True)
        return sanitized, result
    if lane == 'key':
        with pytest.raises(InvalidBundleDraft, match='^Invalid sanitized bundle draft$'):
            BundleGenerator().create_bundle(**args, sanitize_draft=scan)
    else:
        bundle = BundleGenerator().create_bundle(**args, sanitize_draft=scan)
        assert_no_secret(bundle)
        assert verify_bundle_chain(bundle)[0]
    assert reached == [True]


@pytest.mark.parametrize('governance', [SECRET, [], 7])
def test_malformed_governance_has_fixed_failure(governance):
    args = inputs()
    args['governance'] = governance
    with pytest.raises(InvalidBundleDraft, match='^Invalid producer bundle draft$'):
        BundleGenerator().create_bundle(**args, sanitize_draft=lambda draft: (draft, None))


def produced_review_args(shape='normal', intent='feature', risk='comment'):
    from src.analyzer import (DiffAnalyzer, AI_REVIEW_RUBRIC_SCORE_KEYS,
                              AI_REVIEW_ENVELOPE_KEY, AI_REVIEW_SCHEMA_VERSION)
    analyzer = object.__new__(DiffAnalyzer)
    analyzer.max_models_available = 0 if shape == 'disabled' else 1
    analyzer.models = [('openai', 'gpt-4o')]
    analyzer.ai_enabled = shape != 'ai_disabled'
    payload = {'schema_version': AI_REVIEW_SCHEMA_VERSION,
              'summary': 'contact ' + SECRET, 'intent': intent,
              'concerns': ['contact ' + SECRET], 'risk_assessment': risk,
              'confidence': 0.8, 'rubric_scores': dict.fromkeys(AI_REVIEW_RUBRIC_SCORE_KEYS, 3)}
    with patch.object(analyzer, '_call_provider', return_value=(
            json.dumps({AI_REVIEW_ENVELOPE_KEY: payload}), {'model_id': 'gpt-4o'})):
        review = analyzer._get_model_review('openai', 'gpt-4o', '', [], 'default', True)
    assert review['intent'] == intent and not review.get('error')
    if shape == 'failed':
        review = analyzer._fail_closed_review('contact ' + SECRET,
            provider='openai', model_name='gpt-4o', error='InvalidReviewResponse',
            parse_error=True, schema_error=True)
    with patch.object(analyzer, '_parallel_review', return_value=[review]) as provider, \
         patch.object(analyzer, '_parallel_crosscheck', return_value=[review]):
        analysis = analyzer.analyze('', tier_override='L2', deliberate=shape == 'deliberation')
    assert provider.call_count == (0 if shape in ('disabled', 'ai_disabled') else 1)
    args = inputs()
    args['analysis'] = vars(analysis)
    return args


def producer_schema_inventory():
    """Union actual producer dictionary keys, independent of exemption paths."""
    combined = {}
    for shape in ('normal', 'deliberation', 'failed', 'disabled', 'ai_disabled'):
        analysis = produced_review_args(shape)['analysis']
        roots = {'multi_model_review': BundleGenerator._redact_review(analysis['multi_model_review']),
                 'ai_summary': analysis.get('ai_summary') or {},
                 'review_coverage': analysis.get('review_coverage') or {}}
        pending = [(('analysis_snapshot', name), value) for name, value in roots.items()]
        while pending:
            path, value = pending.pop()
            if isinstance(value, dict):
                combined.setdefault(path, set()).update(value)
                pending.extend(((*path, key), child) for key, child in value.items())
            elif isinstance(value, list):
                pending.extend(((*path, int), child) for child in value)
    return combined


@pytest.mark.parametrize('mutation', [None, 'removed_key', 'stale_key',
                                      'stale_path', 'removed_path', 'producer_removed'])
def test_schema_inventory_matches_actual_producers(mutation):
    from src.bundle_generator import _ANALYZER_SCHEMA_KEYS
    actual = {path: set(keys) for path, keys in _ANALYZER_SCHEMA_KEYS.items()}
    expected = producer_schema_inventory()
    path = ('analysis_snapshot', 'multi_model_review')
    if mutation == 'removed_key':
        actual[path].remove('models_used')
    elif mutation == 'stale_key':
        actual[path].add('obsolete_field')
    elif mutation == 'stale_path':
        actual[(*path, 'obsolete')] = {'summary'}
    elif mutation == 'removed_path':
        actual.pop(path)
    elif mutation == 'producer_removed':
        expected[path].remove('models_used')
    with pytest.raises(AssertionError) if mutation else nullcontext():
        assert actual == expected


@pytest.mark.parametrize('shape', ['normal', 'deliberation', 'failed', 'disabled', 'ai_disabled'])
def test_schema_labels_are_excluded_only_at_their_producer_positions(shape):
    schema_names = set().union(*producer_schema_inventory().values())
    args = produced_review_args(shape)
    captured = []
    def capture(draft):
        captured.append(set(draft['_labels']))
        return draft, None
    BundleGenerator().create_bundle(**args, sanitize_draft=capture)
    assert captured.pop().isdisjoint(schema_names)
    args['analysis']['multi_model_review']['extension'] = dict.fromkeys(schema_names, 'ordinary')
    BundleGenerator().create_bundle(**args, sanitize_draft=capture)
    assert schema_names <= captured.pop()


def test_removed_identity_schema_key_cannot_hide_behind_value_protection(monkeypatch):
    from src.bundle_generator import _ANALYZER_SCHEMA_KEYS
    path = ('analysis_snapshot', 'multi_model_review', 'reviews', int)
    monkeypatch.setitem(_ANALYZER_SCHEMA_KEYS, path, _ANALYZER_SCHEMA_KEYS[path] - {'model_name'})
    captured = []
    def capture(draft):
        captured.append(set(draft['_labels']))
        return draft, None
    BundleGenerator().create_bundle(**produced_review_args(), sanitize_draft=capture)
    # Positive control: the same exclusion oracle must reject this real mutant.
    with pytest.raises(AssertionError):
        assert captured.pop().isdisjoint({'model_name'})


@pytest.mark.parametrize('shape', ['normal', 'deliberation', 'failed', 'disabled', 'ai_disabled'])
def test_actual_analyzer_shapes_survive_real_engine(shape):
    args = produced_review_args(shape)
    client = PIIShieldClient(enabled=True, fail_closed=True)
    _, pem, fingerprint = _gen_key()
    bundle = BundleGenerator().create_bundle(**args, attestation_key=pem,
        sanitize_draft=lambda draft: client.sanitize_json_document(draft, preserve_hash_fields=False))
    before = args['analysis']['multi_model_review']
    after = bundle['analysis_snapshot']['multi_model_review']
    assert after['models_used'] == before['models_used']
    if before.get('consensus'):
        assert after['consensus']['consensus_risk'] == before['consensus']['consensus_risk']
    for source, output in zip(before['reviews'], after['reviews']):
        assert output['risk_assessment'] == source['risk_assessment']
        assert output['intent'] == source['intent']
        assert '[HIDDEN' in output['summary']
    assert_no_secret(bundle)
    assert_proofs(bundle, fingerprint)


def test_all_review_classifications_survive_real_engine():
    from src.analyzer import AI_REVIEW_INTENTS, AI_REVIEW_RISK_ASSESSMENTS
    client = PIIShieldClient(enabled=True, fail_closed=True)
    for intent in sorted(AI_REVIEW_INTENTS):
        for risk in sorted(AI_REVIEW_RISK_ASSESSMENTS):
            args = produced_review_args(intent=intent, risk=risk)
            bundle = BundleGenerator().create_bundle(**args,
                sanitize_draft=lambda draft: client.sanitize_json_document(draft, preserve_hash_fields=False))
            mmr = bundle['analysis_snapshot']['multi_model_review']
            assert mmr['rubric_name'] == 'default'
            assert mmr['reviews'][0]['intent'] == intent
            assert mmr['reviews'][0]['risk_assessment'] == risk
            assert mmr['consensus']['consensus_risk'] == risk
            assert bundle['analysis_snapshot']['ai_summary']['intent'] == intent
            assert_no_secret(bundle)
            assert verify_bundle_chain(bundle)[0]


@pytest.mark.parametrize('parent', ['extension', 'concerns', 'string_index'])
@pytest.mark.parametrize('key', ['rubric_name', SECRET])
def test_schema_lookalikes_and_private_keys_still_refuse(parent, key):
    args = produced_review_args()
    mmr = args['analysis']['multi_model_review']
    if parent == 'extension':
        mmr['extension'] = {key: 'ordinary'}
    elif parent == 'concerns':
        mmr['reviews'][0]['concerns'] = [{key: 'ordinary'}]
    else:
        mmr['reviews'][0]['rubric_scores'] = {'0': {key: 'ordinary'}}
    def scan(draft):
        assert key in draft['_labels']
        draft['_labels'] = [label.replace(key, '[HIDDEN:test]') for label in draft['_labels']]
        return draft, None
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(InvalidBundleDraft, match='^Invalid sanitized bundle draft$'):
            generator.create_bundle(**args, sanitize_draft=scan)
    seal.assert_not_called()


@pytest.mark.parametrize('change', ['delete', 'rename'])
def test_schema_key_changes_refuse_before_proofs(change):
    args = produced_review_args()
    def scan(draft):
        mmr = draft['analysis_snapshot']['multi_model_review']
        value = mmr.pop('rubric_name')
        if change == 'rename':
            mmr['other'] = value
        return draft, None
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(InvalidBundleDraft, match='^Invalid sanitized bundle draft$'):
            generator.create_bundle(**args, sanitize_draft=scan)
    seal.assert_not_called()


@pytest.mark.parametrize('identity', ['review-model', SECRET])
def test_schema_key_exclusion_never_exempts_model_identity(identity):
    args = produced_review_args()
    args['analysis']['multi_model_review']['reviews'][0]['model_name'] = identity
    client = PIIShieldClient(enabled=True, fail_closed=True)
    generator = BundleGenerator()
    with patch.object(generator, 'seal_bundle') as seal:
        with pytest.raises(InvalidBundleDraft, match='^Invalid sanitized bundle draft$'):
            generator.create_bundle(**args, sanitize_draft=lambda draft:
                client.sanitize_json_document(draft, preserve_hash_fields=False))
    seal.assert_not_called()
