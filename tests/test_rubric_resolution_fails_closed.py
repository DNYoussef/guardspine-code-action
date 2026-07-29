"""GATE: a rubric that cannot be resolved stops the scan. It never degrades quietly.

Written by the auditor before the change. Two seams, one property.

SEAM A -- STUB RULES WEARING REAL CONTROL IDS. `_load_configured_rubric` falls
back to `_load_legacy_rubric_rules` when a builtin name has no shipped YAML.
That table (LEGACY_RUBRICS) holds three hardcoded regexes per regime, labelled
`164.312.a`, `164.312.b`, `164.312.e` for HIPAA and `3.4`, `6.5`, `8.3` for
PCI. So a scan can emit findings citing genuine HIPAA control ids while the
real 13-rule pack never loaded, and the evidence bundle records "hipaa". An
auditor reading that bundle cannot tell the difference. This is the sharpest
form of the defect this product exists to oppose: a record asserting governance
that did not happen.

SEAM B -- REFUSE, THEN GOVERN WITH SOMETHING ELSE ANYWAY. When the `rubric:`
input names something unavailable from the base ref, entrypoint prints
`::warning::` and returns None, and the scan proceeds under `default`. The
REFUSAL is correct and stays -- it is the phase 2 trust boundary, and a PR must
not supply the policy that reviews it. What is wrong is what follows: five
generic rules govern the change, the run exits green, and nothing the customer
reads says their rubric was not applied.

THE PROPERTY. If the governing rubric cannot be resolved, the scan fails. It
does not substitute a different policy and report success.

THE COST, STATED PLAINLY. A PR that PROPOSES a new rubric file will now fail
until that file is merged to the default branch. That is not a regression; it
is the same rule the pack list already follows, and it is the phase 2 design
intent: "governance changes by merging into the default branch, which is itself
governed". A scan that quietly enforced `default` while the config named
`hipaa` was never giving that PR meaningful review anyway.
"""

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from src.risk_classifier import RiskClassifier


# ---------------------------------------------------------------------------
# Seam A: no stub rules, ever
# ---------------------------------------------------------------------------

def test_no_hardcoded_rules_wear_real_control_ids():
    """The table itself must be gone. Its danger is not that it is a fallback;
    it is that its contents are indistinguishable from real findings."""
    import ast

    src = (ROOT / "src" / "risk_classifier.py").read_text(encoding="utf-8")
    tree = ast.parse(src)

    # Bind to the CODE, not to the text: a docstring explaining why the table
    # was removed is fine, a table is not. An earlier draft of this probe
    # forbade the string anywhere and would have banned its own explanation.
    assigned = {
        t.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for t in node.targets
        if isinstance(t, ast.Name)
    }
    assert "LEGACY_RUBRICS" not in assigned and "RUBRICS" not in assigned, (
        "the stub-rule table is still defined; a scan can still emit findings "
        "citing real control ids from three hardcoded regexes"
    )

    forged = {"164.312.a", "164.312.b", "164.312.e", "3.4", "6.5", "8.3"}
    literals = {
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert not (forged & literals), (
        f"control ids still hardcoded in the classifier: {sorted(forged & literals)}"
    )


def test_a_builtin_name_with_no_yaml_does_not_invent_rules(tmp_path):
    """The behavioural half. A name the catalogue cannot supply must yield no
    rules at all, rather than a plausible-looking stub set."""
    rc = RiskClassifier(rubric="hipaa")
    ids = [r["id"] for r in rc.rubric_rules]
    assert ids, "hipaa should resolve from the shipped catalogue"
    # The real pack, not the three-rule stub.
    assert len(ids) > 3, f"only {len(ids)} rules -- this looks like the stub set"
    assert not {"164.312.a", "164.312.b", "164.312.e"} & set(ids), (
        "the stub rule ids are still what a HIPAA scan produces"
    )


def test_builtin_names_still_lists_the_real_packs():
    """Counterweight: builtin_names folded in the legacy keys. Removing them
    must not make soc2/hipaa/pci-dss stop being recognised names."""
    names = RiskClassifier.builtin_names()
    for expected in ("default", "security", "soc2", "hipaa", "pci-dss"):
        assert expected in names, f"{expected!r} stopped being a known rubric name"


# ---------------------------------------------------------------------------
# Seam B: refuse and stop, not refuse and substitute
# ---------------------------------------------------------------------------

def _repo(tmp_path: Path, base_has_rubric: bool) -> Path:
    repo = tmp_path / "repo"
    (repo / "rubrics").mkdir(parents=True)
    def git(*a):
        subprocess.run(["git", "-c", f"safe.directory={repo}", *a],
                       cwd=str(repo), check=True, capture_output=True, text=True)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.test")
    git("config", "user.name", "t")
    if base_has_rubric:
        (repo / "rubrics" / "policy.yaml").write_text(yaml.dump({
            "name": "policy", "version": "1.0",
            "rules": [{"id": "BASE-1", "severity": "high", "name": "n",
                       "description": "d", "patterns": ["api_key"]}],
        }), encoding="utf-8")
    else:
        (repo / "README").write_text("x", encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "base")
    if not base_has_rubric:
        (repo / "rubrics" / "policy.yaml").write_text(yaml.dump({
            "name": "policy", "version": "9.9",
            "rules": [{"id": "PR-ONLY-1", "severity": "low", "name": "n",
                       "description": "d", "patterns": ["zzz"]}],
        }), encoding="utf-8")
    return repo


def test_an_unresolvable_rubric_raises_rather_than_substituting(tmp_path, monkeypatch):
    """The contract: entrypoint exposes the refusal as an error the caller
    cannot ignore, instead of returning None and letting `default` govern."""
    import entrypoint

    repo = _repo(tmp_path, base_has_rubric=False)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    with pytest.raises(entrypoint.RubricUnavailableError) as exc:
        entrypoint._trusted_rubric_path(repo, "rubrics/policy.yaml")

    msg = str(exc.value)
    assert "rubrics/policy.yaml" in msg, "the error does not name the rubric"
    assert "default" not in msg.lower() or "merge" in msg.lower(), (
        "the error should explain the fix (merge it to the default branch), "
        "not merely mention falling back"
    )


def test_a_rubric_present_on_the_base_ref_still_governs(tmp_path, monkeypatch):
    """Counterweight, the overwhelmingly common case."""
    import entrypoint

    repo = _repo(tmp_path, base_has_rubric=True)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    path = entrypoint._trusted_rubric_path(repo, "rubrics/policy.yaml")
    assert path is not None
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    assert [r["id"] for r in data["rules"]] == ["BASE-1"]


def test_outside_a_pull_request_nothing_changes(tmp_path, monkeypatch):
    """No base ref means no PR to game; refusing here would break push and
    scheduled scans for no security gain."""
    import entrypoint

    repo = _repo(tmp_path, base_has_rubric=True)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)

    assert entrypoint._trusted_rubric_path(repo, "rubrics/policy.yaml") is not None


def test_a_shipped_pack_is_unaffected(tmp_path, monkeypatch):
    """Shipped packs come from the installed distribution, not the repo, so the
    base ref has nothing to say about them and they must keep resolving."""
    import entrypoint

    repo = _repo(tmp_path, base_has_rubric=True)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    resolved = entrypoint._governing_rubric_path(repo, "security")
    assert resolved is not None, "a shipped pack stopped resolving on a PR"
