"""
Comprehensive tests for all codeguard-action fixes.

Covers:
  1. Bundle path relative output (Docker container fix)
  2. Risk driver file/line locations
  3. PR comment rendering with locations
  4. Evidence bundle hash chain integrity
  5. SARIF export with locations
  6. Rubric loading edge cases
  7. Full pipeline dry-run
"""

import json
import os
import sys
import tempfile
import unittest
import uuid
import base64
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "stubs"))
sys.path.insert(0, str(ROOT))

from risk_classifier import RiskClassifier, Finding
from bundle_generator import BundleGenerator, verify_bundle_chain
from pr_commenter import PRCommenter
from sarif_exporter import SARIFExporter
from decision_engine import DecisionPacket, render_decision_card
from entrypoint import map_decision_to_verdict

# Stub GitHub objects for testing
from github import Github


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_DIFF = (
    "diff --git a/src/auth/login.py b/src/auth/login.py\n"
    "index abc1234..def5678 100644\n"
    "--- a/src/auth/login.py\n"
    "+++ b/src/auth/login.py\n"
    "@@ -10,2 +10,4 @@ def login(username, password):\n"
    "     token = generate_token(user)\n"
    "+    # FIXME: credential rotation\n"
    "+    secret_key = os.environ[\"SECRET_KEY\"]\n"
    "     return token\n"
    "diff --git a/src/payments/charge.py b/src/payments/charge.py\n"
    "index 111aaa..222bbb 100644\n"
    "--- a/src/payments/charge.py\n"
    "+++ b/src/payments/charge.py\n"
    "@@ -5,2 +5,4 @@ def charge_card(card_number, amount):\n"
    "     stripe.api_key = API_KEY\n"
    "+    # billing update\n"
    "+    transaction = stripe.Charge.create(amount=amount)\n"
    "     return transaction\n"
)


def make_analysis(files=None, zones=None, added=10, removed=2):
    """Build a minimal analysis dict."""
    return {
        "files": files or [],
        "sensitive_zones": zones or [],
        "lines_added": added,
        "lines_removed": removed,
        "files_changed": len(files or []),
        "diff_hash": "sha256:deadbeef",
    }


def make_zones():
    """Realistic sensitive zones from a payment+auth diff."""
    return [
        {"zone": "auth", "file": "src/auth/login.py", "line": 12},
        {"zone": "crypto", "file": "src/auth/login.py", "line": 13},
        {"zone": "payment", "file": "src/payments/charge.py", "line": 7},
        {"zone": "payment", "file": "src/payments/charge.py", "line": 8},
        {"zone": "config", "file": "src/auth/login.py", "line": 13},
    ]


def make_files():
    """Realistic file list."""
    return [
        {
            "path": "src/auth/login.py",
            "added": 2, "removed": 0,
            "hunks": [{
                "source_start": 10, "source_length": 3,
                "target_start": 10, "target_length": 5,
                "lines": [
                    {"type": "context", "content": "token = generate_token(user)", "line_number": 11},
                    {"type": "add", "content": "# FIXME: credential rotation", "line_number": 12},
                    {"type": "add", "content": 'secret_key = os.environ["SECRET_KEY"]', "line_number": 13},
                    {"type": "context", "content": "return token", "line_number": 14},
                ]
            }],
        },
        {
            "path": "src/payments/charge.py",
            "added": 2, "removed": 0,
            "hunks": [{
                "source_start": 5, "source_length": 2,
                "target_start": 5, "target_length": 4,
                "lines": [
                    {"type": "context", "content": "stripe.api_key = API_KEY", "line_number": 6},
                    {"type": "add", "content": "# billing update", "line_number": 7},
                    {"type": "add", "content": "transaction = stripe.Charge.create(amount=amount)", "line_number": 8},
                    {"type": "context", "content": "return transaction", "line_number": 9},
                ]
            }],
        },
    ]


# ===========================================================================
# TEST SUITE 1: Bundle path relative output
# ===========================================================================

class TestBundlePathRelative(unittest.TestCase):
    """Fix #1: bundle_path output must be relative to workspace."""

    def test_relative_to_posix_workspace(self):
        """Simulate Docker container path resolution (Linux)."""
        workspace = PurePosixPath("/github/workspace")
        bundle = workspace / ".guardspine" / "bundles" / "bundle-pr42-abc1234.json"
        relative = PurePosixPath(str(bundle)[len(str(workspace)) + 1:])
        self.assertEqual(str(relative), ".guardspine/bundles/bundle-pr42-abc1234.json")

    def test_relative_to_workspace_with_pathlib(self):
        """Test Path.relative_to() which is what entrypoint.py uses."""
        workspace = Path("/github/workspace")
        bundle = workspace / ".guardspine" / "bundles" / "bundle-pr42-abc1234.json"
        relative = bundle.relative_to(workspace)
        # On Windows this uses backslashes; on Linux forward slashes.
        # The action runs on Linux, so this is correct.
        parts = relative.parts
        self.assertEqual(parts[0], ".guardspine")
        self.assertEqual(parts[1], "bundles")
        self.assertEqual(parts[2], "bundle-pr42-abc1234.json")

    def test_valueerror_fallback_for_unrelated_paths(self):
        """If bundle is somehow outside workspace, fall through gracefully."""
        workspace = Path("/github/workspace")
        bundle = Path("/tmp/stray/bundle.json")
        try:
            relative = bundle.relative_to(workspace)
        except ValueError:
            relative = bundle  # entrypoint.py fallback
        self.assertEqual(str(relative), str(bundle))

    def test_bundle_dir_mkdir(self):
        """Ensure bundle_dir.mkdir(parents=True) works in temp."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = Path(tmpdir) / ".guardspine" / "bundles"
            bundle_dir.mkdir(parents=True, exist_ok=True)
            self.assertTrue(bundle_dir.exists())
            bundle_path = bundle_dir / "bundle-pr1-abc1234.json"
            bundle_path.write_text('{"test": true}')
            self.assertTrue(bundle_path.exists())


# ===========================================================================
# TEST SUITE 2: Risk driver file/line locations
# ===========================================================================

class TestRiskDriverLocations(unittest.TestCase):
    """Fix #2: risk drivers must include WHERE the change is."""

    def test_zone_drivers_have_locations(self):
        zones = make_zones()
        files = make_files()
        analysis = make_analysis(files=files, zones=zones, added=4, removed=0)

        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        zone_drivers = [d for d in result["risk_drivers"] if d["type"] == "sensitive_zone"]
        self.assertTrue(len(zone_drivers) > 0, "Expected at least one zone driver")

        for driver in zone_drivers:
            self.assertIn("locations", driver, f"Driver {driver['zone']} missing 'locations'")
            self.assertTrue(len(driver["locations"]) > 0, f"Driver {driver['zone']} has empty locations")

    def test_zone_driver_description_contains_file(self):
        zones = [
            {"zone": "auth", "file": "src/auth.py", "line": 42},
            {"zone": "auth", "file": "src/auth.py", "line": 99},
        ]
        analysis = make_analysis(
            files=[{"path": "src/auth.py", "hunks": []}],
            zones=zones, added=5, removed=0,
        )
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        auth_driver = next(
            (d for d in result["risk_drivers"] if d.get("zone") == "auth"), None
        )
        self.assertIsNotNone(auth_driver, "Expected auth zone driver")
        self.assertIn("src/auth.py:42", auth_driver["description"])
        self.assertIn("src/auth.py:99", auth_driver["description"])

    def test_finding_drivers_have_file_line(self):
        zones = make_zones()
        files = make_files()
        analysis = make_analysis(files=files, zones=zones, added=4, removed=0)

        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        finding_drivers = [d for d in result["risk_drivers"] if d["type"] == "policy_finding"]
        for driver in finding_drivers:
            # At minimum, file should be present (line may be None for path-only matches)
            self.assertIn("file", driver, f"Finding driver missing 'file': {driver}")
            self.assertIn("line", driver, f"Finding driver missing 'line': {driver}")

    def test_location_dedup(self):
        """Same file:line appearing twice in zones should only appear once."""
        zones = [
            {"zone": "auth", "file": "src/a.py", "line": 10},
            {"zone": "auth", "file": "src/a.py", "line": 10},  # dupe
            {"zone": "auth", "file": "src/b.py", "line": 20},
        ]
        analysis = make_analysis(
            files=[{"path": "src/a.py", "hunks": []}, {"path": "src/b.py", "hunks": []}],
            zones=zones, added=3, removed=0,
        )
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        auth_driver = next(d for d in result["risk_drivers"] if d.get("zone") == "auth")
        # src/a.py:10 should appear only once
        self.assertEqual(
            auth_driver["locations"].count("src/a.py:10"), 1,
            "Duplicate location not deduped"
        )

    def test_locations_capped_at_3_in_description(self):
        """Description should show at most 3 locations + overflow count."""
        zones = [{"zone": "auth", "file": f"src/f{i}.py", "line": i} for i in range(6)]
        analysis = make_analysis(
            files=[{"path": f"src/f{i}.py", "hunks": []} for i in range(6)],
            zones=zones, added=6, removed=0,
        )
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        auth_driver = next(d for d in result["risk_drivers"] if d.get("zone") == "auth")
        desc = auth_driver["description"]
        # Should have +N more suffix
        self.assertIn("+3 more", desc, f"Expected overflow indicator in: {desc}")
        # Full locations list should still have all 6
        self.assertEqual(len(auth_driver["locations"]), 6)


# ===========================================================================
# TEST SUITE 3: PR comment rendering
# ===========================================================================

class TestPRCommentRendering(unittest.TestCase):
    """Fix #3: PR comment governance template renders correctly with locations."""

    def _make_commenter(self):
        gh = Github("fake-token")
        repo = gh.get_repo("test/repo")
        pr = repo.get_pull(1)
        return PRCommenter(gh, repo, pr), pr

    def test_basic_comment_structure(self):
        commenter, pr = self._make_commenter()
        commenter.post_summary(
            risk_tier="L3",
            risk_drivers=[{
                "type": "sensitive_zone",
                "zone": "auth",
                "count": 2,
                "locations": ["src/auth.py:42", "src/auth.py:99"],
                "description": "2 changes in auth code (`src/auth.py:42`, `src/auth.py:99`)",
            }],
            findings=[{
                "id": "ZONE-AUTH",
                "severity": "high",
                "message": "Sensitive auth code modified",
                "file": "src/auth.py",
                "line": 42,
                "rule_id": "sensitive-auth",
                "zone": "auth",
            }],
            requires_approval=True,
            threshold="L3",
        )
        self.assertEqual(len(pr._comments), 1)
        body = pr._comments[0].body
        self.assertIn("GuardSpine:", body)
        self.assertIn("L3", body)
        self.assertIn("Merge blocked", body)
        self.assertIn("src/auth.py:42", body)

    def test_comment_update_replaces_existing(self):
        commenter, pr = self._make_commenter()
        commenter.post_summary("L1", [], [], False)
        self.assertEqual(len(pr._comments), 1)
        first_body = pr._comments[0].body

        commenter.post_summary("L3", [], [], True)
        self.assertEqual(len(pr._comments), 1)  # still 1 comment, updated
        self.assertNotEqual(pr._comments[0].body, first_body)
        self.assertIn("L3", pr._comments[0].body)

    def test_findings_detail_shows_file_line(self):
        commenter, pr = self._make_commenter()
        commenter.post_summary(
            risk_tier="L2",
            risk_drivers=[],
            findings=[{
                "id": "RUBRIC-DEF-001",
                "severity": "critical",
                "message": "Hardcoded credentials",
                "file": "src/config.py",
                "line": 15,
                "rule_id": "DEF-001",
                "zone": None,
            }],
            requires_approval=False,
        )
        body = pr._comments[0].body
        self.assertIn("`src/config.py:15`", body)
        self.assertIn("Hardcoded credentials", body)

    def test_no_findings_no_crash(self):
        commenter, pr = self._make_commenter()
        commenter.post_summary("L0", [], [], False)
        body = pr._comments[0].body
        self.assertIn("L0", body)
        self.assertNotIn("Findings Summary", body)

    def test_decision_card_respects_human_review_gate(self):
        packet = DecisionPacket(
            decision="merge",
            total_findings=0,
            policy_name="standard",
            risk_tier="L3",
            threshold="L3",
            requires_approval=True,
            review_gate_reason="Risk tier L3 exceeds threshold L3. Human review required.",
        )

        body = render_decision_card(packet)

        self.assertIn("CONDITIONAL - Reviewer action needed", body)
        self.assertIn("Risk tier L3 exceeds threshold L3. Human review required.", body)
        self.assertIn("Human review:** required", body)
        self.assertNotIn("No issues found. Clean merge.", body)


# ===========================================================================
# TEST SUITE 4: Evidence bundle hash chain integrity
# ===========================================================================

class TestBundleIntegrity(unittest.TestCase):
    """Fix #4: bundles must remain valid after code changes."""

    def _make_bundle(self, attestation_key=None):
        pr = SimpleNamespace(
            number=42,
            title="Stub PR",
            created_at=datetime.now(timezone.utc),
            user=SimpleNamespace(login="stub-user"),
            base=SimpleNamespace(ref="main"),
            head=SimpleNamespace(ref="feature"),
        )

        generator = BundleGenerator()
        analysis = make_analysis(files=make_files(), zones=make_zones(), added=4, removed=0)
        risk_result = {
            "risk_tier": "L3",
            "risk_drivers": [{"type": "sensitive_zone", "zone": "auth", "description": "test"}],
            "findings": [{"id": "F1", "severity": "high", "message": "test", "file": "x.py",
                          "line": 1, "rule_id": "R1", "zone": "auth"}],
            "scores": {"file_patterns": 3, "sensitive_zones": 3, "change_size": 1},
            "rationale": "High risk",
        }
        bundle = generator.create_bundle(
            pr=pr, analysis=analysis,
            risk_result=risk_result, repository="test/repo", commit_sha="abc1234567890",
            attestation_key=attestation_key,
        )
        return bundle

    def test_hash_chain_verifies(self):
        bundle = self._make_bundle()
        valid, msg = verify_bundle_chain(bundle)
        self.assertTrue(valid, f"Hash chain failed: {msg}")

    def test_tamper_detection(self):
        bundle = self._make_bundle()
        # Tamper with event data
        bundle["events"][1]["data"]["files_changed"] = 999
        valid, msg = verify_bundle_chain(bundle)
        self.assertFalse(valid, "Tampered bundle should fail verification")
        self.assertIn("Hash mismatch", msg)

    def test_bundle_has_required_fields(self):
        bundle = self._make_bundle()
        self.assertIn("guardspine_spec_version", bundle)
        self.assertIn("bundle_id", bundle)
        self.assertIn("created_at", bundle)
        self.assertIn("context", bundle)
        self.assertIn("events", bundle)
        self.assertIn("hash_chain", bundle)
        self.assertIn("summary", bundle)
        self.assertEqual(bundle["context"]["repository"], "test/repo")
        self.assertEqual(bundle["context"]["pr_number"], 42)

    def test_bundle_events_chain_links(self):
        bundle = self._make_bundle()
        events = bundle["events"]
        self.assertTrue(len(events) >= 3, "Expected at least 3 events")
        # First event should have a hash
        self.assertTrue(len(events[0]["hash"]) == 64, "Hash should be 64 hex chars")
        # Final hash should match last event hash
        self.assertEqual(
            bundle["hash_chain"]["final_hash"],
            events[-1]["hash"],
        )

    def test_bundle_json_serializable(self):
        bundle = self._make_bundle()
        serialized = json.dumps(bundle, default=str)
        self.assertIsInstance(serialized, str)
        reparsed = json.loads(serialized)
        self.assertEqual(reparsed["bundle_id"], bundle["bundle_id"])

    def test_bundle_id_is_deterministic_uuid_v5(self):
        bundle = self._make_bundle()
        parsed = uuid.UUID(bundle["bundle_id"])
        self.assertEqual(parsed.version, 5)
        # Same inputs produce same ID
        bundle2 = self._make_bundle()
        self.assertEqual(bundle["bundle_id"], bundle2["bundle_id"])

    def test_signature_shape_matches_v020_spec(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        bundle = self._make_bundle(attestation_key=pem)
        signatures = bundle.get("signatures", [])
        self.assertEqual(len(signatures), 1)
        sig = signatures[0]

        required = ["signature_id", "algorithm", "signer_id", "signature_value", "signed_at"]
        for field in required:
            self.assertIn(field, sig, f"Missing signature field: {field}")

        self.assertIn(sig["algorithm"], ("ed25519", "rsa-sha256", "ecdsa-p256", "hmac-sha256"))
        self.assertEqual(sig["signer_id"], "guardspine-codeguard")

        # Ensure signature bytes are schema-compatible base64.
        decoded = base64.b64decode(sig["signature_value"], validate=True)
        self.assertTrue(len(decoded) > 0, "Decoded signature bytes should not be empty")

        # Ensure timestamp is ISO 8601 parseable.
        datetime.fromisoformat(sig["signed_at"].replace("Z", "+00:00"))

        # Legacy keys should no longer be emitted.
        self.assertNotIn("type", sig)
        self.assertNotIn("signer", sig)
        self.assertNotIn("timestamp", sig)
        self.assertNotIn("signature", sig)


# ===========================================================================
# TEST SUITE 5: SARIF export with file/line
# ===========================================================================

class TestSARIFExport(unittest.TestCase):
    """SARIF output must include file locations from findings."""

    def test_sarif_includes_line_numbers(self):
        findings = [
            {"id": "ZONE-AUTH", "severity": "high", "message": "Auth modified",
             "file": "src/auth.py", "line": 42, "rule_id": "sensitive-auth", "zone": "auth"},
            {"id": "RUBRIC-DEF-001", "severity": "critical", "message": "Hardcoded creds",
             "file": "src/config.py", "line": 15, "rule_id": "DEF-001", "zone": None},
        ]
        exporter = SARIFExporter()
        sarif = exporter.export(findings, "test/repo", "abc123")

        results = sarif["runs"][0]["results"]
        self.assertEqual(len(results), 2)

        for result in results:
            loc = result["locations"][0]["physicalLocation"]
            self.assertIn("artifactLocation", loc)
            self.assertIn("region", loc, f"Missing region for {result['ruleId']}")
            self.assertIn("startLine", loc["region"])

    def test_sarif_no_line_means_no_region(self):
        findings = [
            {"id": "F1", "severity": "medium", "message": "Path match",
             "file": "src/auth.py", "line": None, "rule_id": "R1", "zone": None},
        ]
        exporter = SARIFExporter()
        sarif = exporter.export(findings, "test/repo", "abc123")

        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertNotIn("region", loc, "No region expected when line is None")


# ===========================================================================
# TEST SUITE 6: Rubric loading edge cases
# ===========================================================================

class TestRubricLoading(unittest.TestCase):
    """Rubric loading must be robust against bad input."""

    def test_bad_regex_skipped_not_fatal(self):
        data = {"rules": [
            {"id": "BAD", "pattern": "[", "severity": "high", "message": "Broken"},
            {"id": "GOOD", "pattern": "payment", "severity": "critical", "message": "Payment"},
        ]}
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(data, f)
            path = Path(f.name)

        classifier = RiskClassifier(rubric="custom", rubric_path=path)
        # BAD rule should be compiled=None and skipped
        self.assertEqual(len(classifier.rubric_errors), 1)
        self.assertIn("BAD", classifier.rubric_errors[0])

        # GOOD rule should still work
        analysis = make_analysis(
            files=[{"path": "src/payments.py", "hunks": [{
                "lines": [{"type": "add", "content": "payment = True", "line_number": 1}]
            }]}],
            zones=[], added=1, removed=0,
        )
        result = classifier.classify(analysis)
        rule_ids = {f["rule_id"] for f in result["findings"]}
        self.assertIn("GOOD", rule_ids)
        self.assertNotIn("BAD", rule_ids)
        path.unlink()

    def test_empty_rubric_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("")
            path = Path(f.name)

        classifier = RiskClassifier(rubric="custom", rubric_path=path)
        self.assertEqual(len(classifier.rubric_rules), 0)
        path.unlink()

    def test_builtin_rubrics_load(self):
        for name in ("default", "soc2", "hipaa", "pci-dss"):
            classifier = RiskClassifier(rubric=name)
            self.assertTrue(len(classifier.rubric_rules) > 0, f"{name} has no rules")

    def test_nonexistent_rubric_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            RiskClassifier(rubric="custom", rubric_path="/nonexistent/rubric.yaml")


# ===========================================================================
# TEST SUITE 7: Full pipeline dry-run
# ===========================================================================

class TestFullPipeline(unittest.TestCase):
    """End-to-end test: analyze -> classify -> bundle -> comment -> SARIF."""

    def test_full_pipeline(self):
        """Simulate the full codeguard-action pipeline without GitHub API."""
        from analyzer import DiffAnalyzer

        # 1. Analyze diff (no AI - no API keys)
        analyzer = DiffAnalyzer(ai_review=False)
        analysis = analyzer.analyze(SAMPLE_DIFF)

        self.assertGreater(analysis["files_changed"], 0)
        self.assertGreater(analysis["lines_added"], 0)
        self.assertTrue(len(analysis["sensitive_zones"]) > 0, "Expected sensitive zones in auth+payment diff")
        self.assertTrue(analysis["diff_hash"].startswith("sha256:"))

        # 2. Classify risk
        classifier = RiskClassifier(rubric="default")
        risk_result = classifier.classify(analysis)

        tier = risk_result["risk_tier"]
        self.assertIn(tier, ("L2", "L3", "L4"), f"Auth+payment diff should be L2+, got {tier}")

        # Check drivers have locations
        zone_drivers = [d for d in risk_result["risk_drivers"] if d["type"] == "sensitive_zone"]
        if zone_drivers:
            for d in zone_drivers:
                self.assertIn("locations", d)

        # 3. Generate evidence bundle
        gh = Github("fake-token")
        repo = gh.get_repo("test/repo")
        pr = repo.get_pull(1)

        generator = BundleGenerator()
        bundle = generator.create_bundle(
            pr=pr, analysis=analysis,
            risk_result=risk_result, repository="test/repo", commit_sha="abc1234567890"
        )

        # Verify hash chain
        valid, msg = verify_bundle_chain(bundle)
        self.assertTrue(valid, f"Bundle hash chain failed: {msg}")

        # 4. Post PR comment
        commenter = PRCommenter(gh, repo, pr)
        commenter.post_summary(
            risk_tier=tier,
            risk_drivers=risk_result["risk_drivers"],
            findings=risk_result["findings"],
            requires_approval=(tier in ("L3", "L4")),
        )
        self.assertEqual(len(pr._comments), 1)
        body = pr._comments[0].body
        self.assertIn("GuardSpine:", body)
        self.assertIn(tier, body)

        # 5. SARIF export
        if risk_result["findings"]:
            exporter = SARIFExporter()
            sarif = exporter.export(risk_result["findings"], "test/repo", "abc1234567890")
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertTrue(len(sarif["runs"][0]["results"]) > 0)

        # 6. Bundle path relative
        workspace = Path("/github/workspace")
        bundle_dir = workspace / ".guardspine" / "bundles"
        bundle_path = bundle_dir / "bundle-pr1-abc1234.json"
        try:
            relative = bundle_path.relative_to(workspace)
        except ValueError:
            relative = bundle_path
        self.assertFalse(str(relative).startswith("/"), "Path should be relative, not absolute")

        print(f"\n{'='*60}")
        print(f"FULL PIPELINE DRY-RUN PASSED")
        print(f"  Risk tier: {tier}")
        print(f"  Findings: {len(risk_result['findings'])}")
        print(f"  Drivers: {len(risk_result['risk_drivers'])}")
        print(f"  Bundle events: {len(bundle['events'])}")
        print(f"  Hash chain: VERIFIED")
        print(f"  Bundle path: {relative}")
        print(f"  PR comment: {len(body)} chars")
        print(f"{'='*60}")


class TestVerdictCompatAlias(unittest.TestCase):
    """Reviewer-style verdict alias for downstream workflows that gate on outputs.verdict.
    See W2.2.5 audit finding: GuardSpine codeguard.yml referenced outputs.verdict since
    inception, but the action never emitted it. This alias closes that gap with a stable
    semantic mapping."""

    def test_merge_maps_to_approve(self):
        self.assertEqual(map_decision_to_verdict("merge"), "APPROVE")

    def test_merge_with_conditions_maps_to_request_changes(self):
        self.assertEqual(map_decision_to_verdict("merge-with-conditions"), "REQUEST_CHANGES")

    def test_block_maps_to_block(self):
        self.assertEqual(map_decision_to_verdict("block"), "BLOCK")

    def test_unknown_decision_maps_to_unknown(self):
        self.assertEqual(map_decision_to_verdict("something-else"), "UNKNOWN")

    def test_empty_decision_maps_to_unknown(self):
        self.assertEqual(map_decision_to_verdict(""), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
