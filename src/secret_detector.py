"""Deterministic secret detector (P3a -- pure detection, no wiring).

codeguard's decision engine hard-blocks ONLY on findings that are
``severity=critical`` AND ``provable=True`` (decision_profiles/standard.yaml).
After P1, every keyword zone and rubric rule is ``provable=False``, so nothing
can legitimately hard-block today. This module is the first genuinely
*deterministic* detector: known credential FORMATS (a PEM private key, a cloud
provider key, a hardcoded credential) are provable facts, not heuristics, so
their findings may carry ``provable=True`` and restore a real block path.

Scope of THIS module (P3a): pure detection only. It returns ``SecretHit``
objects. It does NOT:
  - import or wire into the analyzer / risk_classifier (that is P3b),
  - apply the test-fixture downgrade (policy lives at the wiring layer; see
    the plan's amendment 3 -- test-file hits become provable=False there),
  - run before/after PII-Shield redaction (the caller must feed RAW added
    lines so detection sees the secret, then redact previews/bundles).

Precision policy (deliberately conservative -- a false BLOCK is worse than a
false condition; see plan amendment 1):
  BLOCK   (critical, provable=True): known credential FORMATS only --
          PEM private key, GitHub/Slack/Google tokens, an AWS *secret* key in
          context, or a paired AWS access-key-id + secret in the same set.
  CONDITION (high, provable=False): weaker signals -- a JWT, a lone AWS
          access-key-id (an identifier, not proof: amendment 4), a generic
          ``password=<value>`` assignment, or a high-entropy literal. These
          escalate to a human but never block. Promotion of the entropy tier
          to provable is gated on the P3c eval corpus, not done here.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


REDACTED = "[REDACTED]"  # never echo secret material into a finding


@dataclass(frozen=True)
class SecretHit:
    """One detected secret. ``preview`` is always REDACTED -- the raw value is
    never carried out of this module."""
    kind: str          # private_key_pem | github_token | aws_credential_pair | ...
    severity: str      # critical | high | medium
    provable: bool     # True only for high-confidence known credential formats
    line: int          # 1-based line number within the scanned set (0 if N/A)
    detail: str        # short human label -- no secret material
    preview: str = REDACTED


# --------------------------------------------------------------------------
# Tier A: structural known-credential formats (high precision -> may block)
# (kind, compiled pattern, severity, provable)
# --------------------------------------------------------------------------
_STRUCTURAL_BLOCK = [
    ("private_key_pem",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"),
     "critical", True),
    ("github_token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
     "critical", True),
    ("github_pat",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
     "critical", True),
    ("slack_token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     "critical", True),
    ("google_api_key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
     "critical", True),
]

# Tier A weaker / context signals (condition only -> never block on their own)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# AWS: an access-key-id ALONE is an identifier, not a secret (amendment 4).
_AWS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
# An AWS *secret* key in an aws-secret context IS provable.
_AWS_SECRET_CTX = re.compile(
    r"aws.{0,24}secret.{0,24}[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
    re.IGNORECASE,
)

# Generic hardcoded credential assignment: name = "value"
_GENERIC_ASSIGN = re.compile(
    r"""(?ix)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|
        client[_-]?secret|auth[_-]?token|private[_-]?key)\b
        \s*[:=]\s*['"]([^'"]{8,})['"]""",
    re.VERBOSE,
)

# Quoted token-ish literals for the entropy tier.
_QUOTED_TOKEN = re.compile(r"['\"]([A-Za-z0-9/+_=\-]{16,})['\"]")

# --------------------------------------------------------------------------
# Whitelist: known-safe high-entropy values that must NEVER be flagged.
# --------------------------------------------------------------------------
_HASH_FIELD = re.compile(
    r"\b\w*_hash\b.{0,20}['\"]?(?:sha256:)?[0-9a-fA-F]{64}['\"]?"
)
_LOCK_INTEGRITY = re.compile(r"(?i)integrity['\"]?\s*[:=]\s*['\"]?sha\d{3}-")
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_BARE_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")  # sha256 / git blob, not a secret alone
_PLACEHOLDER = re.compile(
    r"(?i)(?:x{4,}|<[^>]+>|your[_-]|example|changeme|dummy|placeholder|"
    r"redacted|sample|test[_-]?key|fake|\bnull\b|\bnone\b|0{8,})"
)

# Entropy thresholds (conservative here; P3c tunes against the negative corpus).
_ENTROPY_MIN_LEN = 20
_ENTROPY_MIN_BITS = 4.0
_GENERIC_MIN_LEN = 12
_GENERIC_MIN_BITS = 3.0


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_placeholder(token: str) -> bool:
    if _PLACEHOLDER.search(token):
        return True
    if len(set(token)) <= 2:  # "aaaaaaaa", "ababab"
        return True
    return False


def _is_whitelisted(token: str, line: str) -> bool:
    """True when *token* on *line* is a known-safe high-entropy value."""
    if _HASH_FIELD.search(line) or _LOCK_INTEGRITY.search(line):
        return True
    if _UUID.fullmatch(token) or _UUID.search(line):
        return True
    if _BARE_HEX64.match(token):
        return True
    if _is_placeholder(token):
        return True
    return False


# Internal candidate before AWS pairing / dedup.
@dataclass(frozen=True)
class _Candidate:
    kind: str
    severity: str
    provable: bool
    detail: str


def scan_line(text: str) -> list[_Candidate]:
    """Per-line detection. No pairing, no policy. Structural formats first."""
    out: list[_Candidate] = []

    for kind, pat, sev, provable in _STRUCTURAL_BLOCK:
        if pat.search(text):
            out.append(_Candidate(kind, sev, provable, kind.replace("_", " ")))

    if _AWS_SECRET_CTX.search(text):
        out.append(_Candidate("aws_secret_key", "critical", True,
                              "AWS secret access key in context"))

    if _AWS_KEY_ID.search(text):
        # Identifier only -> non-provable advisory unless paired (detect()).
        out.append(_Candidate("aws_access_key_id", "high", False,
                              "AWS access key id (identifier; needs paired secret to block)"))

    if _JWT.search(text):
        out.append(_Candidate("jwt", "high", False, "JSON Web Token"))

    for m in _GENERIC_ASSIGN.finditer(text):
        val = m.group(1)
        if _is_whitelisted(val, text) or _is_placeholder(val):
            continue
        if len(val) >= _GENERIC_MIN_LEN and shannon_entropy(val) >= _GENERIC_MIN_BITS:
            # CONDITION only (provable=False): a name=value assignment is
            # strong but NOT a known credential format, so it must not earn
            # block authority by assertion. Promotion to provable is gated on
            # the P3c secrets negative corpus (David's correction). Structural
            # provider formats above remain provable.
            out.append(_Candidate("hardcoded_credential", "high", False,
                                  "hardcoded credential assignment"))

    for m in _QUOTED_TOKEN.finditer(text):
        tok = m.group(1)
        if _is_whitelisted(tok, text):
            continue
        if len(tok) >= _ENTROPY_MIN_LEN and shannon_entropy(tok) >= _ENTROPY_MIN_BITS:
            # Entropy alone is a CONDITION, never a block (provable=False);
            # promotion is gated on the P3c eval corpus.
            out.append(_Candidate("high_entropy", "high", False,
                                  "high-entropy literal"))

    return out


def detect(added_lines: list[tuple[int, str]]) -> list[SecretHit]:
    """Detect secrets across a set of (line_number, text) added lines.

    Applies AWS pairing (amendment 4): a lone access-key-id stays a
    non-provable advisory; an access-key-id seen together with any AWS secret
    (or a 40-char base64 secret-shaped token) in the same set is upgraded to a
    provable ``aws_credential_pair``. De-duplicates by (kind, line).
    """
    raw: list[tuple[int, _Candidate]] = []
    has_aws_id = False
    has_aws_secret = False
    aws_id_line = 0

    for lineno, text in added_lines:
        for cand in scan_line(text):
            raw.append((lineno, cand))
            if cand.kind == "aws_access_key_id":
                has_aws_id = True
                aws_id_line = lineno
            if cand.kind == "aws_secret_key":
                has_aws_secret = True

    hits: list[SecretHit] = []
    seen: set[tuple[str, int]] = set()

    paired = has_aws_id and has_aws_secret
    for lineno, cand in raw:
        kind, sev, provable = cand.kind, cand.severity, cand.provable
        # Upgrade the lone access-key-id advisory into a provable pair.
        if kind == "aws_access_key_id" and paired:
            kind, sev, provable = "aws_credential_pair", "critical", True
        key = (kind, lineno)
        if key in seen:
            continue
        seen.add(key)
        hits.append(SecretHit(
            kind=kind, severity=sev, provable=provable, line=lineno,
            detail=cand.detail if kind != "aws_credential_pair"
            else "AWS access key id paired with a secret",
        ))
    return hits
