"""Run the selected reporting contract and reject skipped or missing tests."""
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


def main():
    suites = {
        'reporting': ['tests/test_entrypoint_failure_reporting.py'],
        'regressions': ['tests/test_entrypoint_summary_integrity.py',
                        'tests/test_entrypoint_pii_shield.py', 'tests/test_pii_shield.py',
                        'tests/test_pii_shield_failure_contract.py', 'tests/test_antiforgery.py',
                        'tests/test_pii_shield_fatal_result.py', 'tests/test_pii_zone_reconstruction.py',
                        'tests/test_wasm_only_no_http.py'],
    }
    suite = sys.argv[1]
    with tempfile.TemporaryDirectory() as scratch:
        report = Path(scratch) / 'results.xml'
        result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p',
                                 'no:cacheprovider', *suites[suite],
                                 f'--junitxml={report}'], check=False)
        if result.returncode:
            return result.returncode
        cases = ET.parse(report).findall('.//testcase')
        # Measured by the focused and complete candidate runs, not a success claim.
        expected_cases = {'reporting': 36, 'regressions': 107}
        if len(cases) != expected_cases[suite] or any(case.find(tag) is not None for case in cases
                            for tag in ('skipped', 'error', 'failure')):
            raise SystemExit('Incomplete test execution')
        print(f'REPORTING_{suite.upper()}_VERIFIED', len(cases))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
