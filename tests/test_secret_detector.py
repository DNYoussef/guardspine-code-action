"""Unit tests for the P3a pure secret detector.

Amendment 5 (fixture hygiene): NO live-looking provider token is committed as
a contiguous literal. Every token is assembled at runtime from split parts so
GitHub secret scanning does not treat this test corpus as a leak.
"""

import unittest

from src.secret_detector import SecretHit, detect, scan_line, shannon_entropy


# --- synthetic token builders (split assembly: the contiguous secret shape
# --- never appears as a source literal) -----------------------------------

def _varied(n: int) -> str:
    """Deterministic high-entropy-ish filler of length n."""
    base = "Ab3Xy9Zk7Qw2Mn5Pr8Lt1Vc6Hs4Jd0Gf"
    return (base * ((n // len(base)) + 1))[:n]


def make_pem_header() -> str:
    return "-----BEGIN " + "RSA PRIVATE " + "KEY-----"


def make_github_token() -> str:
    return "gh" + "p_" + _varied(36)


def make_github_pat() -> str:
    return "github" + "_pat_" + _varied(82)


def make_slack_token() -> str:
    return "xox" + "b-" + "111111111" + "1-" + _varied(24)


def make_google_key() -> str:
    return "AI" + "za" + _varied(35)


def make_aws_id() -> str:
    return "AK" + "IA" + "ABCDEFGHIJ123456"  # 16 upper/digit chars


def make_aws_secret_line() -> str:
    return "aws_secret_access_key = '" + _varied(40) + "'"


def make_jwt() -> str:
    return "ey" + "J" + _varied(12) + "." + "ey" + "J" + _varied(14) + "." + _varied(20)


class TestStructuralBlockingFormats(unittest.TestCase):
    """Tier A known credential formats -> critical, provable=True (can block)."""

    def _one(self, line):
        hits = detect([(1, line)])
        self.assertTrue(hits, f"expected a hit for: {line[:20]}...")
        return hits[0]

    def test_pem_private_key_is_provable_critical(self):
        h = self._one(make_pem_header())
        self.assertEqual((h.kind, h.severity, h.provable),
                         ("private_key_pem", "critical", True))

    def test_github_token_is_provable_critical(self):
        h = self._one("token = '" + make_github_token() + "'")
        self.assertEqual((h.severity, h.provable), ("critical", True))
        self.assertEqual(h.kind, "github_token")

    def test_github_pat_is_provable_critical(self):
        h = self._one("t = '" + make_github_pat() + "'")
        self.assertEqual((h.severity, h.provable), ("critical", True))

    def test_slack_token_is_provable_critical(self):
        h = self._one("hook = '" + make_slack_token() + "'")
        self.assertEqual((h.severity, h.provable), ("critical", True))

    def test_google_api_key_is_provable_critical(self):
        h = self._one("key = '" + make_google_key() + "'")
        self.assertEqual((h.severity, h.provable), ("critical", True))

    def test_aws_secret_in_context_is_provable_critical(self):
        h = self._one(make_aws_secret_line())
        self.assertEqual((h.kind, h.severity, h.provable),
                         ("aws_secret_key", "critical", True))

    def test_preview_never_echoes_the_secret(self):
        secret = make_github_token()
        hits = detect([(1, "token = '" + secret + "'")])
        for h in hits:
            self.assertEqual(h.preview, "[REDACTED]")
            self.assertNotIn(secret, h.preview)
            self.assertNotIn(secret, h.detail)


class TestConditionOnlySignals(unittest.TestCase):
    """Weaker signals -> high, provable=False (escalate, never block)."""

    def test_lone_aws_access_key_id_is_not_provable(self):
        hits = detect([(1, "AWS_ACCESS_KEY_ID = '" + make_aws_id() + "'")])
        self.assertTrue(hits)
        h = next(x for x in hits if x.kind == "aws_access_key_id")
        self.assertFalse(h.provable, "a lone AKIA id is an identifier, not proof")

    def test_jwt_is_condition_not_block(self):
        hits = detect([(1, "auth = '" + make_jwt() + "'")])
        h = next(x for x in hits if x.kind == "jwt")
        self.assertEqual((h.severity, h.provable), ("high", False))

    def test_high_entropy_literal_is_condition_not_block(self):
        hits = detect([(1, "blob = '" + _varied(28) + "'")])
        h = next((x for x in hits if x.kind == "high_entropy"), None)
        self.assertIsNotNone(h, "expected a high-entropy condition finding")
        self.assertFalse(h.provable, "raw entropy must not block until P3c eval gates it")


class TestAwsPairingUpgrade(unittest.TestCase):
    """Amendment 4: id + secret in the same set -> provable pair."""

    def test_paired_id_and_secret_upgrade_to_provable_pair(self):
        lines = [
            (1, "AWS_ACCESS_KEY_ID = '" + make_aws_id() + "'"),
            (2, make_aws_secret_line()),
        ]
        hits = detect(lines)
        pair = next((x for x in hits if x.kind == "aws_credential_pair"), None)
        self.assertIsNotNone(pair, "id+secret in the same set must pair")
        self.assertEqual((pair.severity, pair.provable), ("critical", True))
        self.assertFalse(any(x.kind == "aws_access_key_id" for x in hits),
                         "the lone-id advisory should be replaced by the pair")


class TestWhitelistSuppressesFalsePositives(unittest.TestCase):
    """Known-safe high-entropy values must produce NO finding."""

    def test_sha256_hash_field_not_flagged(self):
        line = "content_hash = '" + ("abcdef0123456789" * 4) + "'"
        self.assertEqual(detect([(1, line)]), [])

    def test_bare_sha256_commit_not_flagged(self):
        line = "commit = '" + ("0123456789abcdef" * 4) + "'"
        self.assertEqual(detect([(1, line)]), [])

    def test_uuid_not_flagged(self):
        line = "request_id = '12345678-1234-1234-1234-123456789abc'"
        self.assertEqual(detect([(1, line)]), [])

    def test_lockfile_integrity_not_flagged(self):
        line = '  integrity: "sha512-' + _varied(40) + '"'
        self.assertEqual(detect([(1, line)]), [])

    def test_placeholder_credentials_not_flagged(self):
        for val in ("your-api-key-here", "changeme123", "xxxxxxxxxxxx",
                    "<your-token>", "example-secret-value"):
            line = "password = '" + val + "'"
            self.assertEqual(detect([(1, line)]), [],
                             f"placeholder must not flag: {val}")

    def test_structural_format_is_not_suppressed_by_whitelist(self):
        # A PEM is always a secret even on an otherwise innocuous line.
        line = "example_key = " + make_pem_header()
        hits = detect([(1, line)])
        self.assertTrue(any(h.kind == "private_key_pem" and h.provable for h in hits))


class TestGenericAssignment(unittest.TestCase):
    def test_high_entropy_password_assignment_is_provable(self):
        hits = detect([(1, "password = '" + _varied(20) + "'")])
        self.assertTrue(any(h.kind == "hardcoded_credential" and h.provable
                            for h in hits))

    def test_short_or_low_entropy_assignment_not_provable_credential(self):
        # "aaaaaaaa" is low-entropy / placeholder -> no hardcoded_credential.
        hits = detect([(1, "password = 'aaaaaaaa'")])
        self.assertFalse(any(h.kind == "hardcoded_credential" for h in hits))


class TestEntropyHelper(unittest.TestCase):
    def test_entropy_monotonicity(self):
        self.assertLess(shannon_entropy("aaaaaaaa"), shannon_entropy(_varied(8)))

    def test_empty_string_zero_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)


class TestPathAgnostic(unittest.TestCase):
    """P3a is pure: it applies NO test-file downgrade (that policy is P3b)."""

    def test_detector_is_path_agnostic(self):
        # detect() takes no path; provable stays True regardless of where the
        # caller found the line. The test-fixture downgrade happens at wiring.
        h = detect([(1, make_pem_header())])[0]
        self.assertTrue(h.provable)
        self.assertIsInstance(h, SecretHit)


if __name__ == "__main__":
    unittest.main()
