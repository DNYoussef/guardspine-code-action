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
    "entrypoint.py": "59503fb58dbf6ae7d752afdc0b140927a2cdbef660b9ba8104c75b28f9d4d5ff",
    "tests/test_entrypoint_summary_integrity.py": "8c52765acc8ddbd917c8da4953fdeb42d34932ee62ef9de28debe57cafac42fe",
    "tests/test_antiforgery.py": "5514cd590a543ab228a77131344d4562814c0acbe39bb459adfb741b22ced239",
    "docs/operations/adapter-failure-20260908/verify_marker_mutation.py": "ee8a622dae1a0d0770e306c1de5d860d3848729f5ae4091875f0beff6e147041",
    "src/pii_shield.py": "b0df245eb54d6535fd17630c079d010c6d28914694e30fc35f4904b8aa75cabe",
    "tests/test_pii_shield_fatal_result.py": "d1055b3b25efccd3fbbd2fa900bb61363e14a9127ac8c834d3c60d52b8dcfea0",
    "tests/test_pii_shield_failure_contract.py": "02cc609bda4fd4ba05f665627c1cf9ce07500902f0fa4c2f4f84abd65231fd78",
    "tests/test_pii_zone_reconstruction.py": "9f7e16fa9554df7e029ae05422a9a6999b16d59914f6ccf073c724c416529692",
    "tests/test_entrypoint_pii_shield.py": "ed1a7b4b6acbfcb3bf27594d69ae8d44fc142ea53fea5c99ce68106081aef2f9",
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
            "-q", "-p", "no:cacheprovider",
            f"--junitxml={report}",
        ], check=False)
        if completed.returncode:
            return completed.returncode
        cases = ET.parse(report).findall(".//testcase")
        # Measured by the eight-file candidate run, including signed saved bundles.
        assert len(cases) == 107, len(cases)
        assert not any(case.find(tag) is not None for case in cases
                       for tag in ("skipped", "failure", "error"))
        mutation = subprocess.run([
            sys.executable, "-B",
            "docs/operations/adapter-failure-20260908/verify_marker_mutation.py",
        ], check=True, capture_output=True, text=True)
        assert "FATAL_GUARD_REMOVAL_REJECTED" in mutation.stdout
        print("FATAL_GUARD_REMOVAL_REJECTED", flush=True)
        print("EXCLUDED_NOT_RUN tests/test_pii_shield_decimal_regression.py", flush=True)
        print("ENTRYPOINT_SUMMARY_LINUX_107_VERIFIED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
