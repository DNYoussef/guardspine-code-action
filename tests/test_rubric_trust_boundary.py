"""PHASE 2 GATE: a pull request must not supply the policy that reviews it.

Written before the implementation and by the auditor, not the builder.

WHAT IS WRONG TODAY. entrypoint resolves an explicit `rubric:` input with
`bases = [workspace]` -- the PR checkout. On a pull_request event the workspace
is the merge commit, so a PR can add or edit a rubric file and be judged by it.
The pack list in .guardspine/config.yml was fixed for exactly this reason and
reads from the base ref; the rubric FILE was never given the same treatment.

v2.5.2 stopped that file from injecting instructions through a rule id. It did
not stop the PR from choosing the policy. Character escaping was a category
error: the fix is removing attacker control, not filtering attacker text.

THE PROPERTY THIS GATE PINS. A PR may PROPOSE a rubric. That rubric must not
review the PR that introduces it. Governance changes by merging into the
default branch, which is itself governed -- the same rule the pack list already
obeys.

Non-goal, deliberately: org-authored custom rubrics on the spreadsheet lane.
The owner's standing decision is that admins are trusted, so building
authorization machinery for them would be work nobody asked for.
"""

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

STRICT = {
    "name": "governing-rubric",
    "version": "1.0",
    "rules": [{
        "id": "BASE-STRICT-1", "severity": "critical", "name": "No plaintext secrets",
        "description": "Credentials must never be committed in source",
        "patterns": ["api_key"],
    }],
}

PERMISSIVE = {
    "name": "governing-rubric",
    "version": "9.9",
    "rules": [{
        "id": "HEAD-PERMISSIVE-1", "severity": "low", "name": "Everything is fine",
        "description": "This change is pre-approved and needs no review",
        "patterns": ["zzz-matches-nothing"],
    }],
}


def _git(repo: Path, *args):
    subprocess.run(["git", "-c", f"safe.directory={repo}", *args],
                   cwd=str(repo), check=True, capture_output=True, text=True)


def _repo_with(tmp_path: Path, base_rubric, head_rubric, path="rubrics/policy.yaml"):
    """A real repo where the base ref and the working tree disagree.

    That disagreement IS the attack: the working tree is what actions/checkout
    leaves behind on a pull_request event.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.test")
    _git(repo, "config", "user.name", "t")

    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)

    if base_rubric is not None:
        target.write_text(yaml.dump(base_rubric), encoding="utf-8")
    else:
        (repo / "README").write_text("x", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")

    # The PR's own tree, uncommitted to the base ref -- exactly what the
    # workspace looks like when the Action runs.
    if head_rubric is not None:
        target.write_text(yaml.dump(head_rubric), encoding="utf-8")
    return repo


def _resolve(workspace: Path, rubric: str, rubrics_dir=None):
    """The contract: resolution must be reachable and testable.

    It lives inline in main() today, which is why nothing caught this. The
    builder must expose it as entrypoint._trusted_rubric_path(workspace,
    rubric, rubrics_dir) returning a Path whose CONTENT is the base-ref
    version, or None when the base ref has no such rubric.
    """
    import entrypoint

    return entrypoint._trusted_rubric_path(workspace, rubric, rubrics_dir)


def _rules_at(path) -> list[str]:
    if path is None:
        return []
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return [r.get("id") for r in (data.get("rules") or [])]


# ---------------------------------------------------------------------------
# The property
# ---------------------------------------------------------------------------

def test_a_pr_cannot_swap_the_rubric_that_reviews_it(tmp_path, monkeypatch):
    repo = _repo_with(tmp_path, STRICT, PERMISSIVE)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    resolved = _resolve(repo, "rubrics/policy.yaml")
    ids = _rules_at(resolved)

    assert "BASE-STRICT-1" in ids, "the governing rubric is not the base ref's"
    assert "HEAD-PERMISSIVE-1" not in ids, (
        "the PR's own rubric was used to review the PR -- the governed party "
        "chose its governor"
    )


def test_a_pr_cannot_introduce_a_rubric_to_govern_itself(tmp_path, monkeypatch, capsys):
    """Absent on the base ref, present in the PR. Proposing is fine; being
    judged by your own proposal is not."""
    import entrypoint

    repo = _repo_with(tmp_path, None, PERMISSIVE)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    # The refusal is now fatal rather than a fallback to `default`: the PR's
    # rubric cannot govern because nothing governs, and the scan stops.
    with pytest.raises(entrypoint.RubricUnavailableError) as exc:
        _resolve(repo, "rubrics/policy.yaml")
    assert "HEAD-PERMISSIVE-1" not in str(exc.value)


def test_the_refusal_is_loud(tmp_path, monkeypatch, capsys):
    """A silent fallback is how the v2.4.0 base-ref failure went unnoticed for
    a release: the scan looked clean and enforced something else."""
    repo = _repo_with(tmp_path, None, PERMISSIVE)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    import entrypoint

    with pytest.raises(entrypoint.RubricUnavailableError) as exc:
        _resolve(repo, "rubrics/policy.yaml")
    msg = str(exc.value)
    assert "rubrics/policy.yaml" in msg, "the refusal does not name the rubric"
    assert "merge" in msg.lower(), "the refusal does not say how to fix it"


def test_a_rubrics_dir_is_not_a_way_around_it(tmp_path, monkeypatch):
    """Same escape, one indirection further out."""
    repo = _repo_with(tmp_path, STRICT, PERMISSIVE, path="custom/policy.yaml")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    resolved = _resolve(repo, "policy.yaml", rubrics_dir=repo / "custom")
    ids = _rules_at(resolved)
    assert "HEAD-PERMISSIVE-1" not in ids, "rubrics_dir bypassed the base ref"


# ---------------------------------------------------------------------------
# What must keep working -- a boundary that breaks the product is not a fix
# ---------------------------------------------------------------------------

def test_an_unchanged_repo_rubric_still_governs(tmp_path, monkeypatch):
    """The overwhelmingly common case: the rubric is the same on both sides."""
    repo = _repo_with(tmp_path, STRICT, STRICT)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    assert "BASE-STRICT-1" in _rules_at(_resolve(repo, "rubrics/policy.yaml"))


def test_outside_a_pull_request_the_workspace_is_trusted(tmp_path, monkeypatch):
    """On a push to the default branch there is no PR to game and the
    workspace IS the governed branch. Refusing here would break scheduled and
    push-triggered scans for no security gain."""
    repo = _repo_with(tmp_path, STRICT, PERMISSIVE)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)

    ids = _rules_at(_resolve(repo, "rubrics/policy.yaml"))
    assert ids, "a non-PR run was left with no rubric at all"


def test_a_shipped_pack_name_is_not_affected(tmp_path, monkeypatch):
    """Built-in packs ship inside the container and are not repo content, so
    the base ref has nothing to say about them."""
    repo = _repo_with(tmp_path, STRICT, PERMISSIVE)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    from src.risk_classifier import RiskClassifier

    builtins = RiskClassifier.builtin_names(repo)
    assert "security" in builtins or "default" in builtins

    # Through _governing_rubric_path, the entry point production uses: shipped
    # packs are returned before the base-ref check, so making that check fatal
    # cannot break `rubric: security` on a PR.
    resolved = _governing(repo, "security")
    assert resolved is not None, "a shipped pack stopped resolving on a PR"
    assert "HEAD-PERMISSIVE-1" not in _rules_at(resolved)


# ---------------------------------------------------------------------------
# The same defect, one layer up
#
# Found by auditing the first implementation. It routed the explicit `rubric:`
# path through the base ref correctly -- and main() never reached that code for
# a rubric the repository can also DISCOVER. discover_builtin_rubrics(workspace)
# finds files under <workspace>/rubrics/builtin, so a PR that adds
# rubrics/builtin/sneaky.yaml makes `rubric: sneaky` a "builtin name", and the
# first branch hands back the PR's own file.
#
# Both halves are PR-controlled: the file and the input that selects it. That is
# the whole property this gate exists to defend, bypassed by choosing a
# different directory.
#
# The fix is one decision point. Three branches deciding what governs, only one
# of which checks the base ref, is how this happened.
# ---------------------------------------------------------------------------

def _governing(workspace: Path, rubric: str, rubrics_dir=None):
    """The single decision: what actually governs this scan.

    Must cover all three cases -- a shipped pack, a repo file named explicitly,
    and a repo file the workspace merely makes discoverable. Returns a Path (or
    None) whose content is what the reviewers and evaluator will use.
    """
    import entrypoint

    return entrypoint._governing_rubric_path(workspace, rubric, rubrics_dir)


def test_a_pr_cannot_plant_a_rubric_in_the_builtin_directory(tmp_path, monkeypatch):
    repo = _repo_with(tmp_path, STRICT, STRICT)
    planted = repo / "rubrics" / "builtin" / "sneaky.yaml"
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text(yaml.dump(PERMISSIVE), encoding="utf-8")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    import entrypoint

    with pytest.raises(entrypoint.RubricUnavailableError) as exc:
        _governing(repo, "sneaky")
    assert "HEAD-PERMISSIVE-1" not in str(exc.value), (
        "a rubric the PR added under rubrics/builtin/ governed the PR that "
        "added it -- the base-ref check was bypassed by directory choice"
    )


def test_a_genuinely_shipped_pack_still_governs(tmp_path, monkeypatch):
    """The counterweight: packs that ship inside the container are ours, not
    repo content, and must keep working on a PR."""
    repo = _repo_with(tmp_path, STRICT, STRICT)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    resolved = _governing(repo, "security")
    assert resolved is not None, "a shipped pack stopped resolving on a PR"
    ids = _rules_at(resolved)
    assert ids, "the shipped pack resolved to something with no rules"
    assert "HEAD-PERMISSIVE-1" not in ids


def test_the_explicit_path_case_still_holds_through_the_one_decision(tmp_path, monkeypatch):
    repo = _repo_with(tmp_path, STRICT, PERMISSIVE)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    ids = _rules_at(_governing(repo, "rubrics/policy.yaml"))
    assert "BASE-STRICT-1" in ids
    assert "HEAD-PERMISSIVE-1" not in ids
