"""Candidate-only independent execution; never a full integration gate."""
import errno
import hashlib
import importlib.metadata
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


# Git's canonical LF bytes, not the Windows working copy's CRLF bytes.
EXPECTED = {
    "tests/test_bundle_canonicalization.py": "1122e921c498b7ec255c90d82ebf9a383e19a1bd27977a5ee6469b8e06d04f92",
    "tests/test_bundle_id_nonce_and_key_id.py": "da7b9e530fed0f412de1c3aa53acd83369b02ea60b25bedf164793ae45e845f4",
    "tests/test_bundle_records_what_governed.py": "fcc76cd0cce9326c148ff3ef4b1398ca29ac1d06187ae048b2161e72cc1c4341",
    "tests/test_verify_local_bundle_signature.py": "3444f2c73bae86b8d13b623f1bf4dae69d9835dd95a03b41b31cce669c5e01a1",
    "tests/test_analysis_result.py": "610ccc378db78c19a7d785dd1ef5f563b1b9725729211bc80aa957f14a71736f",
    "tests/test_result_contract.py": "e760673afc31aaa8696defc27a4b70d021cc4e7113153a41109dacbf41dd1c8b",
    "tests/test_factcheck_fixes.py": "ce655b181bd91946bf530407985b43b6b94aa4f2fdf8edee544f1f915790f396",
    "tests/test_all_fixes.py": "5705b84c7f5e4b6b9ed4b941a7377687461baaf6c61678489276c6aecf0f7c69",
    "src/canonical_json.py": "6329a310007317fc04bc93609e1c20dec553da3b8bd5eacdf7d1b4848ada6970",
    "src/bundle_generator.py": "85ee96607ce79b24be1c61007a9c40f7c3754e22d7ce2b5da8f99aec8544fea6",
    "tests/test_bundle_draft_sanitization.py": "d3482b5a2829710ce2ef267e8ce56737b3c0e179c5aa1fca7d9096d129b70150",
    "docs/operations/bundle-ordering-20260908/verify_bundle_ordering.py": "ac5ba1c3c5b8344e35c3d97873298e121defb1df042a673af3319a34a4627d85",
    "entrypoint.py": "172452573365d74d4d8f0218d7acd30383b1c88f588de64e0e19298b5f52f45e",
    "tests/test_entrypoint_failure_reporting.py": "9f275ac30eb9705225c352122a4065f52570101b4a4997bd908eb1ab824770a4",
    "tests/test_entrypoint_summary_integrity.py": "eaa3bce31a28ff577bc0410f86fcc2281bed256a0940abd1a31da7a73c322cd3",
    "tests/test_antiforgery.py": "5514cd590a543ab228a77131344d4562814c0acbe39bb459adfb741b22ced239",
    "docs/operations/adapter-failure-20260908/verify_marker_mutation.py": "ee8a622dae1a0d0770e306c1de5d860d3848729f5ae4091875f0beff6e147041",
    "src/pii_shield.py": "fd7ec6a4e6ea42995f6d92f1680467060c545ed96f332eda31257ebf8e2226b0",
    "tests/test_pii_shield_fatal_result.py": "d1055b3b25efccd3fbbd2fa900bb61363e14a9127ac8c834d3c60d52b8dcfea0",
    "tests/test_pii_shield_failure_contract.py": "02cc609bda4fd4ba05f665627c1cf9ce07500902f0fa4c2f4f84abd65231fd78",
    "tests/test_pii_zone_reconstruction.py": "9f7e16fa9554df7e029ae05422a9a6999b16d59914f6ccf073c724c416529692",
    "tests/test_entrypoint_pii_shield.py": "205069fb9d986565da0018961cc0dc3fb0a919f9825c7eb43083d7e7451ca174",
    "tests/test_pii_shield.py": "6bf205593de7d641ef4e60f4eab3ddbd9065155021dabae895404a8988c5f8e9",
    "tests/test_wasm_only_no_http.py": "aa39c96a5f4247ad8599019a52119dcc3ba6883663cce2ef3328ccb39bfb17c8",
    "requirements-ci.txt": "2b6cd69da8318a80e12627731cb264c9fb37543b7aecb69083711d82e81f52c9",
    "tests/test_pii_shield_decimal_regression.py": "febab968ea15dd9ad4700db374d6fedc743271ad7d08b6a328c52efd1ad53189",
}


def main():
    if not __debug__:
        raise SystemExit("verifier must not run under -O")
    assert sys.platform == "linux"
    assert os.getuid() == 65534
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    assert int(status["CapEff"].strip(), 16) == 0
    assert status["NoNewPrivs"].strip() == "1"
    assert status["Seccomp"].strip() == "2"
    assert {path.name for path in Path("/sys/class/net").iterdir()} == {"lo"}
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"CONTROL")
        assert right.recv(7) == b"CONTROL"
    try:
        connection = socket.create_connection(("192.0.2.1", 443), timeout=2)
    except OSError as exc:
        assert exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH), exc.errno
    else:
        connection.close()
        raise AssertionError("network egress is reachable")
    # Positive writable control followed by actual read-only filesystem denial.
    with tempfile.TemporaryDirectory() as scratch:
        probe = Path(scratch) / "write-control"
        probe.write_text("CONTROL")
        assert probe.read_text() == "CONTROL"
        try:
            Path("/work/.confinement-write-control").write_text("MUST NOT WRITE")
        except OSError as exc:
            assert exc.errno == errno.EROFS, exc.errno
        else:
            raise AssertionError("source mount is writable")
        print("LINUX_CONFINEMENT_VERIFIED", flush=True)
        print("Python", platform.python_version(), sys.executable, flush=True)
        for package in ("pii-shield-wasi", "wasmtime", "pytest"):
            print(package, importlib.metadata.version(package), flush=True)
        for name, expected in EXPECTED.items():
            actual = hashlib.sha256(Path(name).read_bytes()).hexdigest()
            if actual != expected:
                raise SystemExit(f"reviewed snapshot mismatch: {name}")
            print(actual, name, flush=True)
        report = Path(scratch) / "results.xml"
        completed = subprocess.run([
            sys.executable, "-m", "pytest", "tests/test_pii_shield_fatal_result.py",
            "tests/test_pii_shield.py", "tests/test_wasm_only_no_http.py",
            "tests/test_pii_shield_failure_contract.py",
            "tests/test_pii_zone_reconstruction.py", "tests/test_entrypoint_pii_shield.py",
            "tests/test_entrypoint_summary_integrity.py", "tests/test_antiforgery.py",
            "tests/test_entrypoint_failure_reporting.py",
            "-q", "-p", "no:cacheprovider",
            f"--junitxml={report}",
        ], check=False)
        try:
            cases = ET.parse(report).findall(".//testcase")
        except (OSError, ET.ParseError):
            cases = []
        # Measured by the nine-file run, including actual entrypoint failure paths.
        reporting_passed = (completed.returncode == 0 and len(cases) == 143
                            and not any(case.find(tag) is not None for case in cases
                                        for tag in ("skipped", "failure", "error")))
        # Attempt both new suites even if another suite fails; no failure is hidden.
        leaf_results = [subprocess.run([
            sys.executable, '-B', 'docs/operations/bundle-ordering-20260908/verify_bundle_ordering.py',
            *args], check=False).returncode for args in ([], ['regressions'])]
        mutation = subprocess.run([
            sys.executable, "-B",
            "docs/operations/adapter-failure-20260908/verify_marker_mutation.py",
        ], check=True, capture_output=True, text=True)
        assert "FATAL_GUARD_REMOVAL_REJECTED" in mutation.stdout
        print("FATAL_GUARD_REMOVAL_REJECTED", flush=True)
        print("EXCLUDED_NOT_RUN tests/test_pii_shield_decimal_regression.py", flush=True)
        if not reporting_passed or any(leaf_results):
            return 1
        print("ENTRYPOINT_REPORTING_LINUX_143_VERIFIED", flush=True)
        print("BUNDLE_ORDERING_LINUX_VERIFIED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
