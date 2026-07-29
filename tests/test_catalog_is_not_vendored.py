"""GATE: this Action does not carry its own rubric catalogue.

Written by the auditor before the change. The consumer half of the catalogue
unification; the producer half landed in GuardSpine#237.

WHAT WAS WRONG. Two catalogues. The dashboard priced from the monorepo's
codeguard/rubrics/builtin; this repo shipped its own rubrics/ into the
container (Dockerfile line 30), and this one is what actually runs. All 13
shared packs were byte-identical, so nothing had drifted in CONTENT -- but
membership had, and a customer who selected sox-itgc got a warning buried in
CI logs and was then governed by `default` while the dashboard had sold them
SOX.

The monorepo side is done: guardspine-prompts 0.2.0 now ships the 22-pack union
and the dashboard reads it. If this repo keeps its own copy, the split is only
half closed and the halves can drift again -- which is precisely how the
vendored renderer survived two releases.

WHY THIS GATE ASSERTS "OUTSIDE THE REPO" AND THE MONOREPO'S DOES NOT. There the
package is developed and installed editable, so resolving inside the checkout
is correct. Here it arrives as an exact-pinned, hashed wheel, so a catalogue
resolving inside this repo means a vendored copy is winning. The property is
different on each side of the same artifact, and asserting the wrong one is a
real mistake I made on the monorepo side and CI caught.

A SECURITY CONSEQUENCE WORTH NAMING. Phase 2 established that a PR must not
supply the policy that reviews it, and shipped_rubrics() exists to separate
packs shipped in the image from repo content a PR controls. Once the shipped
catalogue lives in site-packages, that separation stops depending on a path
comparison: a pull request cannot plant a file into an installed distribution
at all. The boundary gets stronger by construction, so the probes below also
pin that a repo-planted file still cannot masquerade as a shipped pack.
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

# Packs that existed only on the dashboard side before unification. If the
# Action still cannot load these, a paying customer still gets `default`.
FORMERLY_DASHBOARD_ONLY = [
    "cfr-part-11", "cmmc-level1", "cpcsc-level1", "eu-ai-act",
    "gdpr-privacy-by-design", "sox-itgc",
]


def _catalog_dir() -> Path:
    from guardspine_prompts import rubric_dir

    return Path(rubric_dir())


# ---------------------------------------------------------------------------
# One catalogue, and it is not this repo's
# ---------------------------------------------------------------------------

def test_this_repo_ships_no_rubric_catalogue_of_its_own():
    strays = sorted(ROOT.glob("rubrics/builtin/*.yaml"))
    assert not strays, (
        "this Action still carries its own catalogue: "
        f"{[p.name for p in strays[:6]]} ({len(strays)} files)"
    )


def test_the_catalogue_arrives_from_an_installed_distribution():
    from importlib.metadata import distribution

    assert distribution("guardspine-prompts").version
    directory = _catalog_dir()
    assert directory.is_dir()
    assert not str(directory.resolve()).startswith(str(ROOT.resolve())), (
        f"the catalogue resolves inside this repo ({directory}) -- a vendored "
        "copy is still winning"
    )


def test_the_pin_is_exact_and_hashed():
    """This repo installs with --require-hashes. An unpinned catalogue would
    let a compromised release change the rules every scan enforces AND the
    rules every reviewer model is shown, with no diff here."""
    files = sorted(ROOT.glob("requirements*.txt"))
    assert files
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert "guardspine-prompts==0.2.0" in text, (
            f"{path.name} does not pin the catalogue at 0.2.0"
        )
        lines = text.splitlines()
        i = next(n for n, l in enumerate(lines) if l.startswith("guardspine-prompts=="))
        assert "--hash=sha256:" in "\n".join(lines[i:i + 4]), (
            f"{path.name} pins the catalogue with no hash"
        )


# ---------------------------------------------------------------------------
# The engine can now run what the dashboard sells
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pack", FORMERLY_DASHBOARD_ONLY)
def test_a_pack_the_dashboard_sells_actually_loads(pack):
    """Before this change these resolved to nothing and the scan silently fell
    back to `default` -- five generic rules -- while the customer had paid for
    a regulated regime. cmmc-level1 and cpcsc-level1 are enterprise tier."""
    rc = RiskClassifier(config_packs=[pack])
    assert rc.rubric_rules, f"{pack} still loads no rules"
    assert not any("not a pack shipped with this Action" in e
                   for e in rc.rubric_errors), (
        f"{pack} is still unknown to the engine: {rc.rubric_errors}"
    )


def test_the_whole_catalogue_loads():
    """Every pack the package ships must be loadable here. A pack that ships
    but cannot load is the same lie in a new place."""
    broken = []
    for path in sorted(_catalog_dir().glob("*.yaml")):
        rc = RiskClassifier(rubric=path.stem)
        if not rc.rubric_rules:
            broken.append(path.stem)
    assert not broken, f"packs that ship but load nothing: {broken}"


def test_the_short_aliases_still_resolve():
    from guardspine_prompts import RUBRIC_ALIASES

    for alias in RUBRIC_ALIASES:
        rc = RiskClassifier(rubric=alias)
        assert rc.rubric_rules, f"alias {alias!r} resolves to nothing"


# ---------------------------------------------------------------------------
# The trust boundary must survive the move -- and get stronger
# ---------------------------------------------------------------------------

def test_a_pr_cannot_plant_a_file_that_passes_as_a_shipped_pack(tmp_path):
    """shipped_rubrics() is what phase 2 uses to tell packs shipped in the
    image from repo content a PR controls. Planting rubrics/builtin/security
    .yaml in a checkout must not shadow the real one."""
    repo = tmp_path / "repo"
    (repo / "rubrics" / "builtin").mkdir(parents=True)
    (repo / "rubrics" / "builtin" / "security.yaml").write_text(
        yaml.dump({"name": "security", "version": "9.9", "rules": [{
            "id": "PLANTED-BY-A-PR", "severity": "low", "name": "x",
            "description": "y", "patterns": ["zzz"],
        }]}), encoding="utf-8",
    )

    shipped = RiskClassifier.shipped_rubrics()
    assert "security" in shipped, "the shipped catalogue lost `security`"
    resolved = Path(shipped["security"]).resolve()
    assert not str(resolved).startswith(str(repo.resolve())), (
        "a PR-planted file resolved as a shipped pack"
    )
    text = resolved.read_text(encoding="utf-8")
    assert "PLANTED-BY-A-PR" not in text


def test_shipped_packs_live_outside_any_checkout():
    """The structural half of the property above: an installed distribution is
    not something a pull request can write to at all."""
    for name, path in RiskClassifier.shipped_rubrics().items():
        assert not str(Path(path).resolve()).startswith(str(ROOT.resolve())), (
            f"shipped pack {name} resolves inside this repo"
        )
