"""PHASE 5 GATE: there is exactly one renderer, and it is not in this repo.

Written by the auditor before the migration.

The audit's CRITICAL #1 was that this repo carried a vendored copy of
format_rubric_context, kept in step with the canonical implementation by a
golden vector checked into BOTH repos. Each repo compared its own renderer
against its own copy of the vector. No CI ever compared the two
implementations, so canonical and vendored could diverge with both suites
green -- two self-consistent islands.

That is the shape of the v2.2.0 failure, where a bespoke canonical-JSON writer
drifted from the shared one and every signed evidence bundle was rejected,
undetected, for two releases. The answer was never a better gate. It was one
artifact.

So this gate does not check that the copy AGREES with anything. It checks the
copy is GONE, and that the renderer now arrives from an installed distribution
that this repository cannot silently edit.
"""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))


def test_no_renderer_is_defined_in_this_repository():
    """A vendored copy that merely stopped being imported is still a copy
    waiting to be picked up again."""
    offenders = []
    for path in list(ROOT.glob("src/**/*.py")) + list(ROOT.glob("*.py")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "def format_rubric_context" in text:
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, f"a renderer is still defined here: {offenders}"


def test_the_vendored_module_is_deleted():
    assert not (ROOT / "src" / "rubric_context.py").exists(), (
        "src/rubric_context.py still exists"
    )


def test_no_duplicate_vector_remains():
    """The vector existed only to hold two implementations together. With one
    implementation it is a second source of truth with nothing to compare."""
    stale = list(ROOT.glob("tests/**/rubric-prompt-context.json"))
    assert not stale, f"a duplicate corpus copy remains: {[str(p) for p in stale]}"


def test_the_renderer_comes_from_an_installed_distribution():
    from importlib.metadata import distribution

    import guardspine_prompts

    dist = distribution("guardspine-prompts")
    assert dist.version, "guardspine-prompts is not installed as a distribution"

    module_path = Path(guardspine_prompts.__file__).resolve()
    assert not str(module_path).startswith(str(ROOT)), (
        f"the renderer resolves inside this repo ({module_path}) rather than "
        "from the installed package -- the vendored copy is still winning"
    )


def test_the_pin_is_exact_and_hashed():
    """This repo installs with --require-hashes. An unpinned or unhashed
    renderer would let a compromised release change what every reviewer model
    is told, on the next build, with no diff here."""
    reqs = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "guardspine-prompts==" in reqs, "the renderer is not pinned"
    lines = reqs.splitlines()
    idx = next(i for i, line in enumerate(lines) if line.startswith("guardspine-prompts=="))
    following = "\n".join(lines[idx:idx + 4])
    assert "--hash=sha256:" in following, "the pin carries no hash"


def test_the_prompt_still_carries_a_rubrics_rules():
    """The migration must not change what a model sees. Same assertion the
    rubric work has made all along, now against the packaged renderer."""
    from src.analyzer import DiffAnalyzer
    from src.risk_classifier import RiskClassifier

    classifier = RiskClassifier(config_packs=["hipaa-safeguards"])
    prompt = DiffAnalyzer._build_review_prompt(
        DiffAnalyzer.__new__(DiffAnalyzer), "x = 1", [], "default", True,
        rubric_packs=classifier.rubric_prompt_packs(),
    )
    loaded = [r["id"] for r in classifier.rubric_rules]
    assert loaded
    missing = [rid for rid in loaded if rid not in prompt]
    assert not missing, f"rules stopped reaching the model after migrating: {missing}"
    assert "<governance_rubrics>" in prompt
