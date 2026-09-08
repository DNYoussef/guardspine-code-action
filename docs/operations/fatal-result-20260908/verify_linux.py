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
    "src/pii_shield.py": "76be92aaa590eb64a732b295fb6f7f432843fee2586898f57840bd3f553d1023",
    "tests/test_pii_shield_fatal_result.py": "c728a2eb23e20d56c9246c085e1bd42f5e2a61602e8834a105a6e4ae5174be1c",
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
            "-q", "-p", "no:cacheprovider",
            f"--junitxml={report}",
        ], check=False)
        if completed.returncode:
            return completed.returncode
        cases = ET.parse(report).findall(".//testcase")
        # Measured 24 fatal controls plus 30 existing adapter/promise controls.
        assert len(cases) == 54, len(cases)
        assert not any(case.find(tag) is not None for case in cases
                       for tag in ("skipped", "failure", "error"))
        print("EXCLUDED_NOT_RUN tests/test_pii_shield_decimal_regression.py", flush=True)
        print("FATAL_LEAF_LINUX_54_VERIFIED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
