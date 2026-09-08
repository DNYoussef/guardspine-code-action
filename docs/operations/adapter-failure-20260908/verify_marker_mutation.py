"""Prove the fatal test rejects removing the guard, without editing source."""
from pathlib import Path
import sys
import tempfile
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from src import pii_shield


def main():
    source = Path(pii_shield.__file__).read_text(encoding="utf-8")
    guard = 'if sanitized == "[PII_SHIELD_DROP: FATAL_ERROR]":'
    assert source.count(guard) == 1
    mutated = source.replace(guard, 'if False:  # removed guard control')
    exec(compile(mutated, pii_shield.__file__, "exec"), pii_shield.__dict__)
    with tempfile.TemporaryDirectory() as scratch:
        report = Path(scratch) / "mutation.xml"
        code = pytest.main([
            str(ROOT / "tests/test_pii_shield_fatal_result.py")
            + "::test_exact_whole_input_sentinel_collision_fails_closed",
            "-q", "-p", "no:cacheprovider", f"--junitxml={report}",
        ])
        assert code == pytest.ExitCode.TESTS_FAILED, code
        cases = ET.parse(report).findall(".//testcase")
        assert len(cases) == 1
        failure = cases[0].find("failure")
        assert failure is not None
        assert "DID NOT RAISE" in failure.attrib["message"]
    print("FATAL_GUARD_REMOVAL_REJECTED")


if __name__ == "__main__":
    main()
