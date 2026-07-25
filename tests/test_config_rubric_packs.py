"""P1 gate: the Action honors `rubric_packs` from .guardspine/config.yml.

Background: onboarding has always generated a `.guardspine/config.yml`
containing a `rubric_packs:` list, and the Action has never read it -- the file
is decorative. Every onboarded repo therefore ran whatever single `rubric:`
input the workflow happened to hardcode (`default`), regardless of the packs
its own config claimed.

These probes are written BEFORE the implementation and are expected to fail.

GA catalog-is-operational: a pack is only offerable if its rules actually
   COMPILE. Resolving a filename is not enough -- six-sigma.yaml resolves and
   contributes zero enforceable rules.
GB config-is-honored: packs listed in config.yml load, with no `rubric:` input.
GC provenance: every rule records which pack it came from, and duplicate rule
   ids across packs are rejected rather than silently last-wins.
"""

from pathlib import Path

import pytest
import yaml

from src.risk_classifier import RiskClassifier


# --------------------------------------------------------------------------
# GA - catalog is operational, not filename-derived
# --------------------------------------------------------------------------

def _compiled_rule_ids(pack: str) -> list[str]:
    rc = RiskClassifier(rubric=pack)
    return [r["id"] for r in rc.rubric_rules]


def _raw_rule_ids(pack_path: Path) -> list[str]:
    raw = yaml.safe_load(pack_path.read_text(encoding="utf-8")) or {}
    return [str(r.get("id")) for r in (raw.get("rules") or []) if isinstance(r, dict)]


def test_ga_six_sigma_is_operationally_dead():
    """Pin the exact trap: six-sigma resolves as a builtin but every one of its
    rules lacks a pattern, so it enforces nothing. A catalog derived from
    filenames would sell this pack."""
    builtins = RiskClassifier.discover_builtin_rubrics()
    assert "six-sigma" in builtins, "six-sigma should still resolve by filename"
    assert _compiled_rule_ids("six-sigma") == [], (
        "six-sigma unexpectedly has compiled rules; re-check the catalog gate"
    )


def test_ga_operational_packs_lose_no_rules():
    """For a pack we intend to offer, every declared rule must compile.
    A pack that silently drops rules is a pack that under-enforces."""
    builtins = RiskClassifier.discover_builtin_rubrics()
    for pack in ("hipaa-safeguards", "pci-dss-requirements", "soc2-controls"):
        raw = _raw_rule_ids(builtins[pack])
        compiled = _compiled_rule_ids(pack)
        assert compiled == raw, (
            f"{pack}: {len(raw) - len(compiled)} declared rule(s) did not compile"
        )


def test_ga_offerable_packs_exclude_dead_ones():
    """The catalog REPORTS declared-vs-compiled; deciding what to offer is the
    caller's policy. Pin the rule that policy must follow: a pack with zero
    compiled rules enforces nothing and must never be offered."""
    catalog = RiskClassifier.operational_rubric_packs()
    offerable = {p for p, c in catalog.items() if c["compiled"] > 0}

    assert "hipaa-safeguards" in offerable
    assert "six-sigma" in catalog, "catalog should still describe the dead pack"
    assert "six-sigma" not in offerable, "a pack that enforces nothing is offerable"
    # fictional ids the backend invented must never appear at all
    assert "security-baseline" not in catalog
    assert "pii-shield" not in catalog


# --------------------------------------------------------------------------
# GB - config.yml rubric_packs is honored
# --------------------------------------------------------------------------

def _write_config(tmp_path: Path, packs: list[str]) -> Path:
    cfg_dir = tmp_path / ".guardspine"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "config.yml").write_text(
        yaml.dump({"api_url": "https://example.test", "rubric_packs": packs}),
        encoding="utf-8",
    )
    return tmp_path


def test_gb_config_packs_are_loaded(tmp_path):
    """Two packs listed in config.yml, no `rubric:` input -> rules from BOTH."""
    repo = _write_config(tmp_path, ["hipaa-safeguards", "pci-dss-requirements"])
    rc = RiskClassifier(repo_root=repo)

    ids = {r["id"] for r in rc.rubric_rules}
    assert any(i.startswith("HIPAA-") for i in ids), "no HIPAA rules loaded"
    assert any(i.startswith("PCI-") for i in ids), "no PCI-DSS rules loaded"


def test_gb_explicit_rubric_input_still_wins(tmp_path):
    """Back-compat: an explicit `rubric:` overrides config.yml, so existing
    workflows do not change behavior when they upgrade."""
    repo = _write_config(tmp_path, ["hipaa-safeguards"])
    rc = RiskClassifier(rubric="pci-dss-requirements", repo_root=repo)

    ids = {r["id"] for r in rc.rubric_rules}
    assert any(i.startswith("PCI-") for i in ids)
    assert not any(i.startswith("HIPAA-") for i in ids), (
        "config.yml packs leaked in despite an explicit rubric: input"
    )


def test_gb_entrypoint_shaped_call_still_honors_config(tmp_path):
    """Regression: entrypoint resolves `default` to the shipped default.yaml and
    passes it as rubric_path, so a naive "was rubric_path set?" check treats
    every onboarded repo as having explicitly chosen a rubric and silently
    ignores its config.yml. Construct the classifier the way entrypoint does."""
    repo = _write_config(tmp_path, ["hipaa-safeguards"])
    builtins = RiskClassifier.discover_builtin_rubrics(repo)
    assert "default" in builtins, "precondition: default resolves to a shipped file"

    rc = RiskClassifier(
        rubric="default",
        rubric_path=builtins["default"],  # entrypoint pre-resolves this
        repo_root=repo,
        rubric_explicit=False,            # ...but the workflow input was unset
    )
    assert any(r["id"].startswith("HIPAA-") for r in rc.rubric_rules), (
        "config.yml packs ignored when entrypoint pre-resolves the default rubric"
    )


def test_gb_unusable_pack_list_falls_back_never_to_zero(tmp_path):
    """The fleet-wide regression this feature nearly shipped: EVERY repo
    onboarded to date has rubric_packs [security-baseline, pii-shield], neither
    of which is a real pack. Honoring that literally took those repos from the
    default rules to ZERO rules, silently disabling rubric enforcement on
    upgrade. An unusable list must fall back, loudly."""
    repo = _write_config(tmp_path, ["security-baseline", "pii-shield"])
    builtins = RiskClassifier.discover_builtin_rubrics(repo)

    baseline = len(RiskClassifier(rubric="default", rubric_path=builtins["default"]).rubric_rules)
    assert baseline > 0, "precondition: the default rubric enforces something"

    rc = RiskClassifier(
        rubric="default", rubric_path=builtins["default"],
        repo_root=repo, rubric_explicit=False,
    )
    assert len(rc.rubric_rules) == baseline, (
        "upgrading an already-onboarded repo changed how much it enforces"
    )
    assert any("falling back" in e for e in rc.rubric_errors), (
        f"fallback happened silently; errors={rc.rubric_errors}"
    )


def test_gb_explicit_default_is_distinguishable_from_unset(tmp_path):
    """`rubric: default` written on purpose must override config.yml, and the
    Action's own input default must be empty so the two are distinguishable."""
    action = yaml.safe_load((Path(__file__).resolve().parents[1] / "action.yml").read_text())
    assert action["inputs"]["rubric"]["default"] == "", (
        "action.yml default must be '' or an explicit `rubric: default` is "
        "indistinguishable from an omitted input"
    )

    repo = _write_config(tmp_path, ["hipaa-safeguards"])
    builtins = RiskClassifier.discover_builtin_rubrics(repo)
    rc = RiskClassifier(
        rubric="default", rubric_path=builtins["default"],
        repo_root=repo, rubric_explicit=True,
    )
    assert not any(r["id"].startswith("HIPAA-") for r in rc.rubric_rules), (
        "config packs overrode an explicit `rubric: default`"
    )


@pytest.mark.parametrize("evil", ["../outside", "/etc/passwd", "../../secrets"])
def test_gb_pack_names_cannot_escape_the_repo(tmp_path, evil):
    """A pack name comes from a committed file any contributor can edit in a PR,
    so it must never become an arbitrary filesystem read."""
    outside = tmp_path.parent / "outside.yaml"
    outside.write_text(yaml.dump({"rules": [
        {"id": "ESCAPED", "patterns": ["x"], "severity": "critical"}
    ]}), encoding="utf-8")

    repo = _write_config(tmp_path / "repo", [evil])
    rc = RiskClassifier(repo_root=repo)
    assert not any(r["id"] == "ESCAPED" for r in rc.rubric_rules), (
        f"pack name {evil!r} escaped the repo and loaded an outside file"
    )


def test_gb_duplicate_pack_names_do_not_double_report(tmp_path):
    """A repeated pack name must not load its rules twice."""
    once = _write_config(tmp_path / "a", ["hipaa-safeguards"])
    twice = _write_config(tmp_path / "b", ["hipaa-safeguards", "hipaa-safeguards"])
    assert len(RiskClassifier(repo_root=twice).rubric_rules) == \
           len(RiskClassifier(repo_root=once).rubric_rules)


def test_gb_malformed_config_does_not_break_the_scan(tmp_path):
    """A broken config must degrade to prior behavior, not crash the Action."""
    cfg = tmp_path / ".guardspine"
    cfg.mkdir(parents=True)
    (cfg / "config.yml").write_text("rubric_packs: [unclosed\n  :::", encoding="utf-8")
    builtins = RiskClassifier.discover_builtin_rubrics(tmp_path)
    rc = RiskClassifier(rubric="default", rubric_path=builtins["default"], repo_root=tmp_path)
    assert rc.rubric_rules, "malformed config.yml killed rubric enforcement"


def test_ga_catalog_reports_partial_packs_honestly():
    """The catalog must expose declared-vs-compiled so a picker can refuse to
    offer packs that only partly work, and must not lie about `default`."""
    catalog = RiskClassifier.operational_rubric_packs()

    assert catalog["six-sigma"]["compiled"] == 0
    assert catalog["six-sigma"]["declared"] == 15

    # 'default' must report its OWN rules, not whatever a repo config asked for
    assert catalog["default"]["compiled"] == 5, catalog["default"]

    # a partially-dead pack is visible as such rather than looking healthy
    clarity = catalog["clarity"]
    assert clarity["compiled"] < clarity["declared"]

    for stem, counts in catalog.items():
        assert counts["compiled"] <= counts["declared"], stem


def test_gb_missing_config_is_not_an_error(tmp_path):
    """A repo with no config.yml keeps working exactly as before."""
    rc = RiskClassifier(rubric="default", repo_root=tmp_path)
    assert rc.rubric_rules, "default rubric stopped loading without a config.yml"


def test_gb_unknown_pack_is_reported_not_silent(tmp_path):
    """A typo'd pack name must surface as an error, not vanish."""
    repo = _write_config(tmp_path, ["hipaa-safeguards", "definitely-not-a-pack"])
    rc = RiskClassifier(repo_root=repo)

    assert any("definitely-not-a-pack" in e for e in rc.rubric_errors), (
        f"unknown pack was swallowed; errors={rc.rubric_errors}"
    )
    # the valid pack still loads
    assert any(r["id"].startswith("HIPAA-") for r in rc.rubric_rules)


# --------------------------------------------------------------------------
# GC - provenance and duplicate handling
# --------------------------------------------------------------------------

def test_gc_rules_carry_source_pack(tmp_path):
    """Merging must not flatten away which pack produced a rule -- otherwise a
    user cannot answer 'which pack flagged this?'."""
    repo = _write_config(tmp_path, ["hipaa-safeguards", "pci-dss-requirements"])
    rc = RiskClassifier(repo_root=repo)

    by_id = {r["id"]: r for r in rc.rubric_rules}
    hipaa = next(r for i, r in by_id.items() if i.startswith("HIPAA-"))
    pci = next(r for i, r in by_id.items() if i.startswith("PCI-"))

    assert hipaa["source_pack"] == "hipaa-safeguards"
    assert pci["source_pack"] == "pci-dss-requirements"


def test_gc_source_pack_reaches_the_finding(tmp_path):
    """Provenance is only real if it survives into the Finding a USER sees.
    Stamping source_pack on an internal rule dict that nothing reads is theater:
    the answer to 'which pack flagged this?' must not require joining back
    through the classifier's private rule list."""
    repo = _write_config(tmp_path, ["hipaa-safeguards", "pci-dss-requirements"])
    rc = RiskClassifier(repo_root=repo)

    def changed(path: str, content: str) -> dict:
        return {
            "path": path, "additions": 1, "deletions": 0,
            "hunks": [{"lines": [
                {"type": "add", "content": content, "line_number": 10}
            ]}],
        }

    findings = rc._apply_rubric([
        changed("src/records.py", "payload = {'patient_data': r, 'medical_record_id': p}"),
        changed("src/checkout.py", "return f'charged card_number {card_number}'"),
    ])
    assert findings, "no findings produced; probe cannot test provenance"

    packs = {f.source_pack for f in findings}
    assert "hipaa-safeguards" in packs, f"HIPAA provenance missing; got {packs}"
    assert "pci-dss-requirements" in packs, f"PCI provenance missing; got {packs}"
    assert all(f.source_pack for f in findings), "a finding has no source_pack"

    # ...and survives serialization, which is what actually reaches the
    # evidence bundle and the PR comment. Provenance that stops at the
    # in-memory object never reaches a human.
    serialized = [rc._finding_to_dict(f) for f in findings]
    assert {d["source_pack"] for d in serialized} == packs, (
        "source_pack dropped when the finding was serialized"
    )


def test_gc_colliding_rule_ids_keep_both_packs_enforcing(tmp_path):
    """A rule id claimed by two packs must NOT cost either pack its enforcement.

    Rejected two weaker designs: last-wins (the existing merge_rubrics helper)
    silently discards one pack's severity/patterns, and drop-both lets an
    unrelated pack disable another pack's critical control by naming collision --
    both make the Action enforce less than the config asked for. Identity is
    (source_pack, rule_id), so both survive and each is attributable."""
    packs_dir = tmp_path / ".guardspine" / "rubrics"
    packs_dir.mkdir(parents=True, exist_ok=True)
    for name, sev in (("alpha", "low"), ("beta", "critical")):
        (packs_dir / f"{name}.yaml").write_text(
            yaml.dump({
                "name": name,
                "rules": [{
                    "id": "SHARED-001",
                    "severity": sev,
                    "description": f"from {name}",
                    "patterns": ["password"],
                }],
            }),
            encoding="utf-8",
        )
    (tmp_path / ".guardspine" / "config.yml").write_text(
        yaml.dump({"rubric_packs": ["alpha", "beta"]}), encoding="utf-8"
    )

    rc = RiskClassifier(repo_root=tmp_path)
    shared = [r for r in rc.rubric_rules if r["id"] == "SHARED-001"]
    assert len(shared) == 2, (
        f"expected both packs' SHARED-001 to survive, got {len(shared)}"
    )
    assert {r["source_pack"] for r in shared} == {"alpha", "beta"}
    # the stricter severity is still enforceable -- nothing was amputated
    assert "critical" in {r["severity"] for r in shared}
