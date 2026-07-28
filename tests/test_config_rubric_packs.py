"""P1 gate: the Action honors `rubric_packs` from .guardspine/config.yml.

Onboarding has always written a `rubric_packs:` list into every repo's
config.yml, and the Action never read it, so every onboarded repo ran whatever
single `rubric:` its workflow hardcoded regardless of its own config.

TRUST BOUNDARY (the load-bearing part): the pack list is supplied BY THE CALLER
from the BASE REF, never read from the workspace. actions/checkout leaves the PR
head on disk, so a config read from there lets a PR choose the policy that
judges it -- ship a one-rule pack matching nothing, point rubric_packs at it,
and obvious violations produce zero findings. The classifier therefore takes a
list, and entrypoint reads it with `git show <base>:...`.

GA catalog: a pack is only offerable if its rules COMPILE (six-sigma.yaml ships
   15 rules and zero patterns -- it resolves and enforces nothing).
GB loading: caller-supplied packs load; explicit `rubric:` still wins; an
   unusable list falls back rather than silently enforcing nothing.
GC provenance: findings carry the pack that produced them.
GD trust: PR-controlled files can never become policy.
"""

from pathlib import Path

import pytest
import yaml

from src.risk_classifier import RiskClassifier


def _packs(*names: str) -> list[str]:
    """Build the trusted list exactly as entrypoint does: parse config TEXT."""
    return RiskClassifier.parse_config_packs(yaml.dump({"rubric_packs": list(names)}))


def _default_path() -> Path:
    return RiskClassifier.shipped_rubrics()["default"]


def _changed(path: str, content: str) -> dict:
    return {
        "path": path, "additions": 1, "deletions": 0,
        "hunks": [{"lines": [{"type": "add", "content": content, "line_number": 10}]}],
    }


# --------------------------------------------------------------------------
# GA - catalog is operational, not filename-derived
# --------------------------------------------------------------------------

def test_ga_six_sigma_is_operationally_dead():
    """Pin the exact trap: six-sigma resolves by filename but every rule lacks a
    pattern, so it enforces nothing. A filename-derived catalog would sell it."""
    assert "six-sigma" in RiskClassifier.shipped_rubrics()
    assert RiskClassifier(rubric="six-sigma").rubric_rules == []


def test_ga_operational_packs_lose_no_rules():
    """For a pack we intend to offer, every declared rule must compile."""
    shipped = RiskClassifier.shipped_rubrics()
    for pack in ("hipaa-safeguards", "pci-dss-requirements", "soc2-controls"):
        raw = yaml.safe_load(shipped[pack].read_text(encoding="utf-8"))["rules"]
        compiled = RiskClassifier(rubric=pack).rubric_rules
        assert [r["id"] for r in compiled] == [str(r["id"]) for r in raw], (
            f"{pack}: {len(raw) - len(compiled)} declared rule(s) did not compile"
        )


def test_ga_offerable_packs_exclude_dead_ones():
    """The catalog REPORTS declared-vs-compiled; a pack with zero compiled rules
    enforces nothing and must never be offered by a picker built on it."""
    catalog = RiskClassifier.operational_rubric_packs()
    offerable = {p for p, c in catalog.items() if c["compiled"] > 0}

    assert "hipaa-safeguards" in offerable
    assert "six-sigma" in catalog, "catalog should still describe the dead pack"
    assert "six-sigma" not in offerable
    # fictional ids the backend invented must never appear at all
    assert "security-baseline" not in catalog
    assert "pii-shield" not in catalog


def test_ga_catalog_reports_partial_packs_honestly():
    catalog = RiskClassifier.operational_rubric_packs()
    assert catalog["six-sigma"] == {"declared": 15, "compiled": 0}
    # 'default' reports its OWN rules, not whatever a repo config asked for
    assert catalog["default"]["compiled"] == 5
    clarity = catalog["clarity"]
    assert clarity["compiled"] < clarity["declared"], "partial pack looks healthy"
    for stem, counts in catalog.items():
        assert counts["compiled"] <= counts["declared"], stem


# --------------------------------------------------------------------------
# GB - loading, precedence, and the never-enforce-less guarantee
# --------------------------------------------------------------------------

def test_gb_config_packs_are_loaded():
    """Two packs, no explicit `rubric:` -> rules from BOTH."""
    rc = RiskClassifier(config_packs=_packs("hipaa-safeguards", "pci-dss-requirements"))
    ids = {r["id"] for r in rc.rubric_rules}
    assert any(i.startswith("HIPAA-") for i in ids), "no HIPAA rules loaded"
    assert any(i.startswith("PCI-") for i in ids), "no PCI-DSS rules loaded"


def test_gb_explicit_rubric_input_still_wins():
    """Back-compat: an explicit `rubric:` overrides the pack list, so upgrading
    never changes an existing workflow's behavior."""
    rc = RiskClassifier(
        rubric="pci-dss-requirements", config_packs=_packs("hipaa-safeguards")
    )
    ids = {r["id"] for r in rc.rubric_rules}
    assert any(i.startswith("PCI-") for i in ids)
    assert not any(i.startswith("HIPAA-") for i in ids)


def test_gb_entrypoint_shaped_call_still_honors_packs():
    """entrypoint pre-resolves `default` to the shipped default.yaml and passes
    it as rubric_path; a naive "was a path supplied?" check would treat every
    onboarded repo as having chosen explicitly and ignore its packs."""
    rc = RiskClassifier(
        rubric="default",
        rubric_path=_default_path(),      # entrypoint pre-resolves this
        rubric_explicit=False,            # ...but the workflow input was unset
        config_packs=_packs("hipaa-safeguards"),
    )
    assert any(r["id"].startswith("HIPAA-") for r in rc.rubric_rules)


def test_gb_explicit_default_is_distinguishable_from_unset():
    """`rubric: default` written on purpose must override the pack list, which
    requires action.yml's input default to be empty."""
    action = yaml.safe_load((Path(__file__).resolve().parents[1] / "action.yml").read_text())
    assert action["inputs"]["rubric"]["default"] == "", (
        "action.yml default must be '' or an explicit `rubric: default` is "
        "indistinguishable from an omitted input"
    )
    rc = RiskClassifier(
        rubric="default", rubric_path=_default_path(),
        rubric_explicit=True, config_packs=_packs("hipaa-safeguards"),
    )
    assert not any(r["id"].startswith("HIPAA-") for r in rc.rubric_rules)


def test_gb_unusable_pack_list_falls_back_never_to_zero():
    """The fleet-wide regression this nearly shipped: EVERY repo onboarded to
    date lists [security-baseline, pii-shield], neither of which is real.
    Honoring that literally took those repos from 5 default rules to ZERO,
    silently disabling rubric enforcement on upgrade."""
    baseline = len(RiskClassifier(rubric="default", rubric_path=_default_path()).rubric_rules)
    assert baseline > 0, "precondition: the default rubric enforces something"

    rc = RiskClassifier(
        rubric="default", rubric_path=_default_path(), rubric_explicit=False,
        config_packs=_packs("security-baseline", "pii-shield"),
    )
    assert len(rc.rubric_rules) == baseline, "upgrade changed how much it enforces"
    assert any("falling back" in e for e in rc.rubric_errors), (
        f"fallback happened silently; errors={rc.rubric_errors}"
    )


def test_gb_partially_valid_list_reports_the_bad_entry():
    """A typo must surface, not vanish, even though the good pack still loads."""
    rc = RiskClassifier(config_packs=_packs("hipaa-safeguards", "definitely-not-a-pack"))
    assert any("definitely-not-a-pack" in e for e in rc.rubric_errors)
    assert any(r["id"].startswith("HIPAA-") for r in rc.rubric_rules)


def test_gb_no_packs_keeps_prior_behavior():
    rc = RiskClassifier(rubric="default", rubric_path=_default_path(), config_packs=[])
    assert rc.rubric_rules, "default rubric stopped loading with no packs"


def test_gb_aliases_do_not_double_load():
    """`hipaa` and `hipaa-safeguards` are the same pack."""
    once = RiskClassifier(config_packs=_packs("hipaa-safeguards")).rubric_rules
    both = RiskClassifier(config_packs=_packs("hipaa", "hipaa-safeguards")).rubric_rules
    assert len(both) == len(once), "an alias loaded the same pack twice"


def test_gb_duplicate_pack_names_do_not_double_report():
    once = RiskClassifier(config_packs=_packs("hipaa-safeguards")).rubric_rules
    twice = RiskClassifier(
        config_packs=_packs("hipaa-safeguards", "hipaa-safeguards")
    ).rubric_rules
    assert len(twice) == len(once)


@pytest.mark.parametrize("text", ["", "not: a mapping", "[1,2,3]", "packs: [x\n :::"])
def test_gb_malformed_config_yields_no_packs(text):
    """Broken config degrades to prior behavior, never crashes the Action."""
    assert RiskClassifier.parse_config_packs(text) == []


def test_gb_pack_list_is_bounded():
    many = _packs(*[f"pack-{i}" for i in range(200)])
    assert len(many) <= RiskClassifier.MAX_CONFIG_PACKS


# --------------------------------------------------------------------------
# GC - provenance
# --------------------------------------------------------------------------

def test_gc_source_pack_reaches_the_finding_and_survives_serialization():
    """Provenance is only real if it survives into what a user sees. Stamping an
    internal rule dict nothing reads is theater."""
    rc = RiskClassifier(config_packs=_packs("hipaa-safeguards", "pci-dss-requirements"))
    findings = rc._apply_rubric([
        _changed("src/records.py", "payload = {'patient_data': r, 'medical_record_id': p}"),
        _changed("src/checkout.py", "return f'charged card_number {card_number}'"),
    ])
    assert findings, "no findings produced; probe cannot test provenance"

    packs = {f.source_pack for f in findings}
    assert "hipaa-safeguards" in packs, f"HIPAA provenance missing; got {packs}"
    assert "pci-dss-requirements" in packs, f"PCI provenance missing; got {packs}"
    assert all(f.source_pack for f in findings)

    serialized = [rc._finding_to_dict(f) for f in findings]
    assert {d["source_pack"] for d in serialized} == packs, (
        "source_pack dropped when the finding was serialized"
    )


def test_gc_colliding_rule_ids_keep_both_packs_enforcing(tmp_path):
    """A rule id claimed by two packs must NOT cost either pack its enforcement.
    Rejected two weaker designs: last-wins silently discards one pack's
    severity/patterns, and drop-both lets an unrelated pack disable another
    pack's critical control by naming coincidence. Identity is
    (source_pack, rule_id), so both survive and each is attributable."""
    rc = RiskClassifier(config_packs=_packs("soc2-controls", "hipaa-safeguards"))
    by_pack: dict[str, set[str]] = {}
    for r in rc.rubric_rules:
        by_pack.setdefault(r["source_pack"], set()).add(r["id"])
    assert set(by_pack) == {"soc2-controls", "hipaa-safeguards"}
    # every rule of each pack is present -- nothing was amputated by merging
    for pack, ids in by_pack.items():
        alone = {r["id"] for r in RiskClassifier(rubric=pack).rubric_rules}
        assert ids == alone, f"{pack} lost rules when merged"


# --------------------------------------------------------------------------
# GD - trust boundary: a PR must not be able to choose its own policy
# --------------------------------------------------------------------------

def test_gd_classifier_ignores_config_on_disk(tmp_path):
    """The classifier must NOT read .guardspine/config.yml from the workspace.
    That file is the PR's copy; honoring it is the self-governance bypass."""
    cfg = tmp_path / ".guardspine"
    cfg.mkdir(parents=True)
    (cfg / "config.yml").write_text(
        yaml.dump({"rubric_packs": ["hipaa-safeguards"]}), encoding="utf-8"
    )
    rc = RiskClassifier(
        rubric="default", rubric_path=_default_path(),
        repo_root=tmp_path, rubric_explicit=False,
    )
    assert not any(r["id"].startswith("HIPAA-") for r in rc.rubric_rules), (
        "classifier read the PR's own config.yml from disk"
    )


def test_gd_pr_cannot_supply_its_own_pack_file(tmp_path):
    """A pack file committed in the PR must not be reachable from the pack list.
    Reproduces the bypass: a valid one-rule pack matching nothing, selected by
    name, previously produced zero findings on obvious payment code."""
    packs_dir = tmp_path / ".guardspine" / "rubrics"
    packs_dir.mkdir(parents=True)
    (packs_dir / "harmless.yaml").write_text(yaml.dump({
        "name": "harmless",
        "rules": [{"id": "NOOP-1", "severity": "info", "description": "never matches",
                   "patterns": ["zzzz_never_occurs_zzzz"]}],
    }), encoding="utf-8")

    rc = RiskClassifier(
        rubric="default", rubric_path=_default_path(), rubric_explicit=False,
        repo_root=tmp_path, config_packs=_packs("harmless"),
    )
    assert not any(r["id"] == "NOOP-1" for r in rc.rubric_rules), (
        "a PR-committed rubric became policy"
    )
    # and enforcement fell back rather than dropping to the attacker's empty set
    assert rc.rubric_rules, "fell through to zero enforcement"


def _shadow_repo(tmp_path: Path) -> Path:
    """A PR that commits its own copy of a SHIPPED pack name, neutered."""
    shadow_dir = tmp_path / "rubrics" / "builtin"
    shadow_dir.mkdir(parents=True)
    (shadow_dir / "hipaa-safeguards.yaml").write_text(yaml.dump({
        "name": "hipaa-safeguards",
        "rules": [{"id": "FAKE-1", "severity": "info", "description": "neutered",
                   "patterns": ["zzzz_never_occurs_zzzz"]}],
    }), encoding="utf-8")
    return tmp_path


def test_gd_pr_cannot_shadow_a_shipped_pack_via_config(tmp_path):
    rc = RiskClassifier(repo_root=_shadow_repo(tmp_path),
                        config_packs=_packs("hipaa-safeguards"))
    ids = {r["id"] for r in rc.rubric_rules}
    assert "FAKE-1" not in ids, "a PR shadowed a shipped pack"
    assert any(i.startswith("HIPAA-") for i in ids), "real HIPAA pack did not load"


def test_gd_pr_cannot_shadow_a_shipped_pack_via_explicit_rubric(tmp_path):
    """The config path was guarded first, but the EXPLICIT `rubric:` path
    resolved through discover_builtin_rubrics(), which searched repo dirs before
    shipped ones and kept the first match. Reproduced: `rubric: hipaa` loaded
    only the PR's NOOP rule. Shipped must win for every resolution path."""
    repo = _shadow_repo(tmp_path)
    builtins = RiskClassifier.discover_builtin_rubrics(repo)
    rc = RiskClassifier(rubric="hipaa", rubric_path=builtins["hipaa"],
                        repo_root=repo, rubric_explicit=True)
    ids = {r["id"] for r in rc.rubric_rules}
    assert "FAKE-1" not in ids, "explicit rubric: loaded a PR-shadowed pack"
    assert any(i.startswith("HIPAA-") for i in ids), "real HIPAA pack did not load"


def test_gd_repo_may_still_add_its_own_uniquely_named_rubric(tmp_path):
    """Shipped-wins must not stop a repo adding rubrics of its own; it only
    stops a repo taking over a name the Action ships."""
    d = tmp_path / "rubrics" / "builtin"
    d.mkdir(parents=True)
    (d / "myteam.yaml").write_text(yaml.dump({
        "name": "myteam",
        "rules": [{"id": "MINE-1", "severity": "low", "description": "x",
                   "patterns": ["todo"]}],
    }), encoding="utf-8")
    assert "myteam" in RiskClassifier.discover_builtin_rubrics(tmp_path)


@pytest.mark.parametrize("evil", ["../outside", "/etc/passwd", "../../secrets",
                                  "\\\\server\\share\\x", "C:/Windows/win.ini"])
def test_gd_pack_names_cannot_escape(evil):
    """Pack names resolve against shipped packs only; nothing else is reachable."""
    rc = RiskClassifier(config_packs=[evil])
    assert rc.rubric_rules == [] or all(
        r["source_pack"] != evil for r in rc.rubric_rules
    ), f"pack name {evil!r} resolved to something"


# --------------------------------------------------------------------------
# GE - the base-ref read actually works inside the action's container
#
# The whole GD trust boundary is worthless if the read that enforces it fails
# and falls back. It did: v2.4.0 shipped with no test over
# _base_ref_config_packs at all, and on the first live PR git refused the
# workspace ("dubious ownership" -- the action runs as root against a checkout
# owned by the runner user), so the warning path swallowed it and every repo
# scanned with the default pack. The scan looked clean and enforced the wrong
# policy, which is the exact failure mode this product sells against.
# --------------------------------------------------------------------------

def _git(repo, *args):
    import subprocess
    subprocess.run(["git", *args], cwd=str(repo), check=True,
                   capture_output=True, text=True)


def _repo_with_config(tmp_path, packs, branch="main"):
    repo = tmp_path / "repo"
    (repo / ".guardspine").mkdir(parents=True)
    _git(repo.parent, "init", "-q", "-b", branch, str(repo))
    _git(repo, "config", "user.email", "t@example.test")
    _git(repo, "config", "user.name", "t")
    (repo / ".guardspine" / "config.yml").write_text(
        yaml.dump({"api_url": "x", "rubric_packs": list(packs)}), encoding="utf-8",
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "config")
    return repo


def test_ge_packs_are_read_from_a_real_base_ref(tmp_path, monkeypatch):
    from entrypoint import _base_ref_config_packs

    # Canonical pack names, deliberately. This test is about WHERE the pack
    # list is read from, not about alias resolution. It previously used "dora"
    # as an arbitrary placeholder, which silently became a real alias when the
    # DORA pack shipped -- the reader canonicalised it and the test broke for a
    # reason that had nothing to do with base refs.
    repo = _repo_with_config(tmp_path, ["security", "clarity"])
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    assert _base_ref_config_packs(repo) == ["security", "clarity"]


def test_ge_a_short_alias_is_canonicalised_on_read(tmp_path, monkeypatch):
    """The behaviour the placeholder above was testing by accident. A repo may
    write the short name; what comes back is the pack that actually governs."""
    from entrypoint import _base_ref_config_packs

    repo = _repo_with_config(tmp_path, ["dora"])
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    assert _base_ref_config_packs(repo) == ["dora-ict-requirements"]


def test_ge_the_pr_copy_is_not_what_gets_read(tmp_path, monkeypatch):
    """Same repo, but the working tree now says something else. The committed
    base-ref copy is what counts."""
    from entrypoint import _base_ref_config_packs

    repo = _repo_with_config(tmp_path, ["security"])
    (repo / ".guardspine" / "config.yml").write_text(
        yaml.dump({"rubric_packs": ["attacker-pack"]}), encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    assert _base_ref_config_packs(repo) == ["security"]


def test_ge_git_is_told_the_workspace_is_safe(tmp_path, monkeypatch):
    """Pins the specific fix. The ownership refusal cannot be reproduced
    portably in a test -- it needs two uids -- so the flag that prevents it is
    asserted directly."""
    import subprocess
    from entrypoint import _base_ref_config_packs

    seen = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 128, "", "fatal: dubious ownership")

    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setattr(subprocess, "run", fake_run)
    _base_ref_config_packs(Path("/github/workspace"))

    assert seen, "git was never invoked"
    for cmd in seen:
        assert f"safe.directory={Path('/github/workspace')}" in cmd, (
            f"git invoked without the workspace marked safe: {cmd}"
        )


def test_ge_a_failed_read_says_why(tmp_path, monkeypatch, capsys):
    """A warning that cannot distinguish 'no config' from 'git refused' is how
    this went unnoticed."""
    import subprocess
    from entrypoint import _base_ref_config_packs

    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 128, "", "fatal: dubious ownership"),
    )
    assert _base_ref_config_packs(Path("/github/workspace")) == []
    assert "dubious ownership" in capsys.readouterr().out
