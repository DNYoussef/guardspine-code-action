"""Properties the WASM path must hold, now that the engine is upstream.

This file used to test our hand-rolled wasmtime adapter
(`src/adapters/pii_wasm_client.py`). That adapter is gone -- redaction now
runs through the published `pii-shield-wasi` package -- but the PROPERTIES it
protected did not stop mattering because the implementation moved.

Deleting a security test because the code it covered was replaced is how a
protection quietly disappears during a migration. So each test here asks the
same question of the new engine, and where the answer is now upstream's to
guarantee rather than ours, it checks the OBSERVABLE behaviour instead of the
internals.

The properties, and why each was written:

  - CI secrets must not reach the sandbox. An Actions runner holds the repo
    token and every configured secret in its environment; an engine that
    inherits the process environment carries all of it in.
  - Raw PII must not linger on disk. The old adapter staged input through a
    temp file to satisfy wasmtime's stdin API and unlinked it immediately.
    Whatever the new engine does internally, no readable copy of the input
    may survive the call.
  - Hostile input must not crash the run. Binary and malformed text reach
    this path from real diffs, and a crash fails the whole action.
  - The safe-regex whitelist must not be settable from the environment. A
    prior audit found `PII_SAFE_REGEX_LIST` set to a wildcard disabled ALL
    redaction. An environment variable that turns the shield off is a
    bypass, not a feature. (In 2.1.1 the engine ignores well-formed values
    and exits on malformed ones -- see the test's docstring -- so setting
    it is no longer a bypass, but it is still an outage waiting to happen.)
"""

from __future__ import annotations

import pathlib
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("pii_shield")

from src.pii_shield import PIIShieldClient  # noqa: E402


SECRET_MARKER = "ghp_TESTSECRETVALUE1234567890abcdefghij"


def _shield(**kw):
    return PIIShieldClient(enabled=True, **kw)


def test_a_ci_secret_in_the_environment_does_not_reach_the_output(monkeypatch):
    """Observable form of "the sandbox does not inherit CI secrets".

    The WASI env is the package's business now, so this asserts the thing
    that would actually hurt: nothing from the runner's environment appears
    in redacted output.
    """
    monkeypatch.setenv("GITHUB_TOKEN", SECRET_MARKER)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SECRET_MARKER)

    result = _shield().sanitize_text("Contact alice@example.com today")
    assert SECRET_MARKER not in result.sanitized_text, (
        "a value from the runner environment appeared in redacted output"
    )


def test_no_readable_copy_of_the_input_survives_the_call(tmp_path, monkeypatch):
    """Raw PII must not linger on disk.

    The engine may still stage input through a temp file -- an
    implementation detail we no longer own -- but nothing readable may be
    left behind. Point the temp directory at an empty tree and check it.
    """
    staging = tmp_path / "staging"
    staging.mkdir()
    for var in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(var, str(staging))
    monkeypatch.setattr(tempfile, "tempdir", str(staging), raising=False)

    secret = "alice.private@example.com"
    result = _shield().sanitize_text("Contact {} today".format(secret))
    assert secret not in result.sanitized_text

    for path in staging.rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes(), (
                "raw input survived on disk at {}".format(path.name)
            )


# ids= is not cosmetic. pytest writes the parameter into
# PYTEST_CURRENT_TEST, and a 200k-character payload blows past the Windows
# 32767-char environment-variable limit -- erroring the RUN rather than the
# assertion, which looks like a code failure and is not one. The large-input
# case is worth keeping, so it gets a name instead of being shrunk.
@pytest.mark.parametrize("payload", [
    b"\x00\x01\x02\xff\xfe binary garbage".decode("latin-1"),
    "x" * 200_000,
    "",
    "\n\n\n\t\t",
], ids=["binary", "very-large", "empty", "whitespace-only"])
def test_hostile_input_does_not_crash_the_run(payload):
    """Binary and malformed text reach this path from real diffs. A crash
    fails the whole action, which is worse than imperfect redaction of
    garbage."""
    try:
        out = _shield(fail_closed=False).sanitize_text(payload)
    except Exception as exc:  # noqa: BLE001 -- not crashing IS the assertion
        pytest.fail("hostile input crashed the shield: {}".format(exc))
    assert isinstance(out.sanitized_text, str)


def test_we_never_hand_the_engine_a_safe_regex_list():
    """The old bypass is gone; setting the variable is now useless or fatal.

    A prior audit found `PII_SAFE_REGEX_LIST` set to a wildcard disabled
    ALL redaction in the vendored binary -- an environment variable that
    switched the shield off. In pii-shield-wasi 2.1.1 that bypass is
    closed, measured both ways: a well-formed [{"pattern","name"}] list is
    accepted and IGNORED (output identical even with a ".*" wildcard),
    and anything else -- invalid JSON, a bare string, an object --
    terminates the WASM runtime with exit 1 from loadConfig.

    So the property is no longer "a wildcard must not disable redaction".
    It is that WE must never populate that variable for the engine:
    populating it cannot restore the old feature, and a malformed value
    turns every redaction into an outage. entrypoint.py did EXACTLY this
    -- `os.environ["PII_SAFE_REGEX_LIST"] = ...` on every run, straight
    from a documented action input -- which the first version of this
    gate missed by checking only src/pii_shield.py. Both files are gated
    now.

    Checked against CODE, not raw text: comments in both files name the
    variable precisely to explain why it is never set, and a grep-based
    gate would fail on the explanation -- or get "fixed" by deleting it.
    Docstrings are stripped first for the same reason (they ARE in the
    AST, unlike comments).
    """
    import ast

    import src.pii_shield as module

    repo_root = pathlib.Path(module.__file__).resolve().parents[1]
    for source_file in (pathlib.Path(module.__file__),
                        repo_root / "entrypoint.py"):
        tree = ast.parse(source_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
                body = getattr(node, "body", None)
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    body.pop(0)
        for node in ast.walk(tree):
            # os.environ["PII_SAFE_REGEX_LIST"] = ... / .setdefault(...)
            if isinstance(node, ast.Constant) and node.value == "PII_SAFE_REGEX_LIST":
                raise AssertionError(
                    "{} names PII_SAFE_REGEX_LIST in executable code -- the "
                    "engine ignores well-formed values and dies on malformed "
                    "ones, so setting it is a no-op or an outage".format(
                        source_file.name
                    )
                )


def test_redaction_is_deterministic_within_a_run():
    """The diff contract depends on it: the same input must not produce two
    different outputs, or an unchanged value reads as changed."""
    shield = _shield()
    text = "Contact alice@example.com and bob@example.org"
    assert (shield.sanitize_text(text).sanitized_text
            == shield.sanitize_text(text).sanitized_text)


def test_the_engine_import_cannot_bind_to_this_repos_own_module():
    """The shadowing hazard, gated because its bad case is silent.

    `src/pii_shield.py` and the installed package are BOTH named
    `pii_shield`. With src/ on sys.path a bare import binds to our module,
    and depending on layout that either explodes or -- far worse -- returns
    something importable that does nothing, so sanitization would look
    configured and silently be a no-op.
    """
    import sys

    src_dir = str(Path(__file__).resolve().parents[1] / "src")
    sys.path.insert(0, src_dir)          # force the collision
    try:
        from src.pii_shield import _load_wasm_engine

        shield_cls, _config_cls = _load_wasm_engine()
        assert shield_cls.__module__.startswith("pii_shield"), (
            "loaded {} -- not the installed engine".format(shield_cls.__module__)
        )
        assert hasattr(shield_cls, "redact"), "loaded object cannot redact"

        import src.pii_shield as ours

        assert hasattr(ours, "PIIShieldClient"), (
            "the package displaced our module in sys.modules"
        )
    finally:
        if src_dir in sys.path:
            sys.path.remove(src_dir)
