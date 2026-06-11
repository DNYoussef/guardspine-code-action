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


class TestUnquotedAndJsonKeys(unittest.TestCase):
    """Real .env/YAML secrets are commonly UNQUOTED, and JSON keys are quoted.
    Both must be handled (P3 core claim: a credential anywhere is detected)."""

    def test_unquoted_aws_secret_blocks(self):
        for line in ("AWS_SECRET_ACCESS_KEY=" + _varied(40),     # env, no quotes
                     "aws_secret_access_key: " + _varied(40)):    # yaml scalar
            hits = detect([(1, line)])
            self.assertTrue(any(h.kind == "aws_secret_key" and h.provable
                                for h in hits),
                            f"unquoted AWS secret must be provable: {line[:24]}")

    def test_unquoted_aws_pair_blocks(self):
        line = "AWS_ACCESS_KEY_ID=" + make_aws_id() + " AWS_SECRET_ACCESS_KEY=" + _varied(40)
        hits = detect([(1, line)])
        self.assertTrue(any(h.kind in ("aws_credential_pair", "aws_secret_key")
                            and h.provable for h in hits),
                        "unquoted AWS id+secret must produce a provable block")

    def test_unquoted_generic_credential_conditions(self):
        for line in ("API_KEY=" + _varied(24),               # env high-entropy
                     "api_key: " + ("abcdef0123456789" * 4)):  # yaml 64hex
            hits = detect([(1, line)])
            self.assertTrue(hits, f"unquoted credential must flag: {line[:18]}")
            self.assertFalse(any(h.provable for h in hits),
                             "generic/entropy stays non-provable (condition)")

    def test_quoted_json_safe_keys_do_not_flag(self):
        # `"commit": "<hex>"` and `"content_hash": "<hex>"` are safe -> no
        # finding (the key parse must accept a quoted JSON key).
        h = "abcdef0123456789" * 4
        for line in ('"commit": "' + h + '"',
                     '"content_hash": "' + h + '"',
                     'commit: ' + h):  # unquoted yaml safe key
            self.assertEqual(detect([(1, line)]), [],
                             f"safe key (json/yaml) must not flag: {line[:18]}")


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

    def test_hex64_in_hash_context_still_whitelisted(self):
        # A 64-hex in a hash/commit context is a content id, not a secret.
        for line in ("content_hash = '" + ("abcdef0123456789" * 4) + "'",
                     "commit = '" + ("0123456789abcdef" * 4) + "'",
                     "checksum: '" + ("fedcba9876543210" * 4) + "'"):
            self.assertEqual(detect([(1, line)]), [],
                             f"safe-context hex must stay whitelisted: {line[:20]}")

    def test_hex64_in_secret_context_is_NOT_whitelisted(self):
        # The hole: api_key/password = <64 hex> must NOT be globally suppressed
        # just because it is 64 hex. It must at least condition.
        hexval = "abcdef0123456789" * 4
        for line in ("api_key = '" + hexval + "'",
                     "password: '" + hexval + "'"):
            hits = detect([(1, line)])
            self.assertTrue(
                hits,
                f"64-hex in a secret context must produce a finding: {line[:20]}",
            )

    def test_uuid_in_identifier_context_still_whitelisted(self):
        u = "12345678-1234-1234-1234-123456789abc"
        for line in ("request_id = '" + u + "'",
                     "trace_id: '" + u + "'",
                     "uuid = '" + u + "'"):
            self.assertEqual(detect([(1, line)]), [],
                             f"identifier-context UUID must stay whitelisted: {line[:18]}")

    def test_uuid_in_secret_context_is_NOT_whitelisted(self):
        # Same class as the hex hole: a UUID as a credential value must not be
        # globally suppressed just because it is a UUID.
        u = "12345678-1234-1234-1234-123456789abc"
        for line in ("api_key: '" + u + "'",
                     "password = '" + u + "'"):
            hits = detect([(1, line)])
            self.assertTrue(
                hits,
                f"UUID in a secret context must produce a finding: {line[:18]}",
            )

    def test_safe_context_in_trailing_comment_does_NOT_whitelist(self):
        # Comment-smuggling: a safe-context word AFTER the value (in a comment)
        # must not whitelist a secret-context value. Context comes from the KEY.
        h = "abcdef0123456789" * 4
        u = "12345678-1234-1234-1234-123456789abc"
        for line in ('api_key: "' + h + '"  # commit id',
                     'api_key: "' + u + '"  # request_id from old system',
                     "password = '" + h + "'  # sha256 of nothing"):
            hits = detect([(1, line)])
            self.assertTrue(
                hits,
                f"a safe word in a trailing comment must not whitelist: {line[:18]}",
            )

    def test_safe_context_in_key_still_whitelists_with_trailing_comment(self):
        # The legit direction: a real key-context value stays whitelisted even
        # when a comment follows.
        h = "abcdef0123456789" * 4
        u = "12345678-1234-1234-1234-123456789abc"
        for line in ('commit = "' + h + '"  # bump version',
                     'request_id = "' + u + '"  # incoming trace'):
            self.assertEqual(detect([(1, line)]), [],
                             f"key-context value must stay whitelisted: {line[:18]}")

    def test_multi_assignment_smuggle_does_NOT_whitelist(self):
        # A safe-context word in a DIFFERENT assignment on the same line must
        # not whitelist a secret-context value. Context is taken from the
        # current assignment's key only (exact match offset, not line.find).
        h = "abcdef0123456789" * 4
        h2 = "0123456789abcdef" * 4
        u = "12345678-1234-1234-1234-123456789abc"
        sri = "sha512-" + ("Ab3Xy9Zk" * 6)[:40]
        for line in (f'commit = "{h}"; api_key = "{h}"',           # same hex reused
                     f'request_id = "{u}"; api_key = "{u}"',        # same uuid reused
                     f'content_hash = "{h}"; api_key = "{h2}"',     # different hex
                     f'integrity: "{sri}"; api_key = "{h}"',        # global integrity
                     f'COMMIT="{h}" API_KEY="{h}"',                 # env / whitespace sep
                     f'REQUEST_ID="{u}" API_KEY="{u}"',             # env uuid
                     f'INTEGRITY="{sri}" API_KEY="{h}"'):           # env integrity
            hits = detect([(1, line)])
            self.assertTrue(
                hits,
                f"a safe word in another assignment must not whitelist: {line[:24]}",
            )

    def test_multi_assignment_legit_values_still_whitelist(self):
        h = "abcdef0123456789" * 4
        u = "12345678-1234-1234-1234-123456789abc"
        for line in (f'commit = "{h}"', f'request_id = "{u}"',
                     f'content_hash = "{h}"', f'object_id = "{h}"',
                     f'COMMIT="{h}"', f'REQUEST_ID="{u}"'):  # env-style legit
            self.assertEqual(detect([(1, line)]), [],
                             f"legit key-context value must whitelist: {line[:18]}")

    def test_structural_format_is_not_suppressed_by_whitelist(self):
        # A PEM is always a secret even on an otherwise innocuous line.
        line = "example_key = " + make_pem_header()
        hits = detect([(1, line)])
        self.assertTrue(any(h.kind == "private_key_pem" and h.provable for h in hits))


class TestGenericAssignment(unittest.TestCase):
    def test_high_entropy_password_assignment_is_condition_not_provable(self):
        # David's correction: a generic name=value assignment is NOT a known
        # credential format, so it conditions (high) but never earns block
        # authority by assertion. Only structural provider formats are provable.
        hits = detect([(1, "password = '" + _varied(20) + "'")])
        cred = next((h for h in hits if h.kind == "hardcoded_credential"), None)
        self.assertIsNotNone(cred, "expected a hardcoded_credential condition")
        self.assertEqual((cred.severity, cred.provable), ("high", False))

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
