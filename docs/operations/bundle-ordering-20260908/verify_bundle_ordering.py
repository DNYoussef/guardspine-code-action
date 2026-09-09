"""Run an explicit suite and require execution of its complete collected inventory."""
from pathlib import Path
from collections import Counter
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


REGRESSIONS = [
    'test_entrypoint_failure_reporting', 'test_entrypoint_summary_integrity',
    'test_entrypoint_pii_shield', 'test_pii_shield', 'test_pii_shield_failure_contract',
    'test_pii_shield_fatal_result', 'test_pii_zone_reconstruction', 'test_wasm_only_no_http',
    'test_antiforgery', 'test_bundle_canonicalization', 'test_bundle_id_nonce_and_key_id',
    'test_bundle_records_what_governed', 'test_verify_local_bundle_signature',
    'test_analysis_result', 'test_result_contract', 'test_factcheck_fixes', 'test_all_fixes',
]

# Existing strict consent gate, not a passing test or newly allowed skip.
CONSENT_XFAIL = 'test_customer_content_does_not_leave_the_customers_ci'
CONSENT_REASON = ("Finding #9 is NOT closed by this phase and must not be silently "
                  "claimed. With pii_shield_enabled defaulting to 'false', model prose "
                  "-- the customer's own code -- still leaves their CI for the "
                  "GuardSpine backend inside the bundle. That is a consent decision "
                  "for the owner, not a string-escaping fix. This xfail is the honest "
                  "record; flip it when the decision is made.")


def main():
    regression = sys.argv[1:] == ['regressions']
    if sys.argv[1:] and not regression:
        raise SystemExit('unknown suite')
    files = [f'tests/{name}.py' for name in REGRESSIONS] if regression else [
        'tests/test_bundle_draft_sanitization.py']
    # Identical collection in Git checkouts and standalone immutable exports.
    command = [sys.executable, '-B', '-m', 'pytest', '-c', os.devnull,
               '--rootdir=.', '-o', 'addopts=', '-q', '-p', 'no:cacheprovider', *files]
    environment = {**os.environ, 'PYTEST_ADDOPTS': '', 'PYTHONDONTWRITEBYTECODE': '1'}
    collected = subprocess.run([*command, '--collect-only'], capture_output=True,
                               text=True, check=True, env=environment)
    nodes = [line for line in collected.stdout.splitlines()
             if line.startswith('tests/') and '::' in line]
    if not nodes or len(nodes) != len(set(nodes)):
        raise SystemExit('missing or duplicate collected inventory')
    with tempfile.TemporaryDirectory() as scratch:
        report = Path(scratch) / 'results.xml'
        result = subprocess.run([*command, f'--junitxml={report}'], check=False, env=environment)
        if result.returncode:
            return result.returncode
        cases = ET.parse(report).findall('.//testcase')
        expected = []
        for node in nodes:
            address, bracket, parameters = node.partition('[')
            parts = address.split('::')
            parts[0] = parts[0].removesuffix('.py').replace('/', '.')
            expected.append(('.'.join(parts[:-1]), parts[-1] + bracket + parameters))
        executed = [(case.get('classname'), case.get('name')) for case in cases]
        skipped = [case for case in cases if case.find('skipped') is not None]
        expected_xfail = (len(skipped) == 1 and skipped[0].get('name') == CONSENT_XFAIL
                          and skipped[0].get('classname') == 'tests.test_result_contract'
                          and skipped[0].find('skipped').get('type') == 'pytest.xfail'
                          and skipped[0].find('skipped').get('message') == CONSENT_REASON)
        if (Counter(executed) != Counter(expected)
                or any(case.find(tag) is not None for case in cases for tag in ('error', 'failure'))
                or (not expected_xfail if regression else bool(skipped))):
            raise SystemExit('incomplete execution')
        if regression:
            print('EXISTING_CONSENT_XFAIL_NOT_PASSED', CONSENT_XFAIL)
        print('BUNDLE_REGRESSIONS_VERIFIED' if regression else 'BUNDLE_ORDERING_VERIFIED', len(cases))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
