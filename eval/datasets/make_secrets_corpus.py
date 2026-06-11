"""Generate the P3c secrets eval corpus at runtime.

Amendment 5 (fixture hygiene): provider-token shapes are assembled from split
parts and written to eval/samples/secrets/ at eval time. The generated .patch
files are gitignored, so no live-looking token literal is ever committed.

Layout produced (consumed by run_eval.py --dataset secrets --tier L0):
  eval/samples/secrets/vulnerable/*.patch  -> real credential formats; MUST
      flag (they hard-block: critical + provable).
  eval/samples/secrets/clean/*.patch       -> known-safe high-entropy values
      placed so they produce ZERO findings (no block AND no condition), which
      a strict --max-fp 5 gate requires.

Run: python eval/datasets/make_secrets_corpus.py
"""

from __future__ import annotations

import shutil
from pathlib import Path

_OUT = Path(__file__).resolve().parents[1] / "samples" / "secrets"


# --- synthetic token builders (split assembly; never a contiguous literal) --

def _varied(n: int) -> str:
    base = "Ab3Xy9Zk7Qw2Mn5Pr8Lt1Vc6Hs4Jd0Gf"
    return (base * ((n // len(base)) + 1))[:n]


def pem() -> str:
    return "-----BEGIN " + "RSA PRIVATE " + "KEY-----"


def github_token() -> str:
    return "gh" + "p_" + _varied(36)


def slack_token() -> str:
    return "xox" + "b-" + "1111111111" + "-" + _varied(24)


def google_key() -> str:
    return "AI" + "za" + _varied(35)


def aws_secret_line() -> str:
    return "aws_secret_access_key = '" + _varied(40) + "'"


def sha256() -> str:
    return ("abcdef0123456789" * 4)  # 64 hex chars


def uuid() -> str:
    return "12345678-1234-1234-1234-123456789abc"


# --- diff writer ----------------------------------------------------------

def _patch(path: str, added: list[str]) -> str:
    body = "".join("+" + line + "\n" for line in added)
    return (
        f"diff --git a/{path} b/{path}\n"
        "index 1111111..2222222 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -1,1 +1,{len(added) + 1} @@\n"
        " context\n"
        f"{body}"
    )


# VULNERABLE: real credential formats -> must flag (block).
_VULNERABLE = {
    "pem_in_source": ("src/keys.py", [pem()]),
    "pem_in_config_yaml": ("deploy/values.yaml", [pem()]),
    "github_token_in_source": ("src/client.py", ["gh_token = '" + github_token() + "'"]),
    "slack_token_in_source": ("src/notify.py", ["hook = '" + slack_token() + "'"]),
    "google_key_in_source": ("src/maps.py", ["api = '" + google_key() + "'"]),
    "aws_secret_in_source": ("src/aws.py", [aws_secret_line()]),
    # Regression for the 64-hex-in-secret-context hole: a 64-hex api_key in a
    # .yaml (where P2 suppresses topic zones) must NOT be a full miss. It is a
    # generic credential -> conditions (flagged), not block.
    "hex_api_key_in_yaml": ("config/app.yaml", ['  api_key: "' + sha256() + '"']),
    # Same class as the hex hole, for UUIDs: a UUID credential value in a
    # .yaml must condition (flag), not be a full miss.
    "uuid_api_key_in_yaml": ("config/svc.yaml", ['  api_key: "' + uuid() + '"']),
    # Comment-smuggling: a safe-context word in a TRAILING COMMENT must not
    # whitelist a secret-context value. Both must still condition.
    "hex_api_key_comment_smuggle": ("config/a.yaml", ['  api_key: "' + sha256() + '"  # commit id']),
    "uuid_api_key_comment_smuggle": ("config/b.yaml", ['  api_key: "' + uuid() + '"  # request_id from old system']),
    # Multi-assignment smuggling: a safe-context word in a DIFFERENT assignment
    # on the same line must not whitelist the secret value.
    "hex_multi_assign_smuggle": ("src/cfg.py", ['commit = "' + sha256() + '"; api_key = "' + sha256() + '"']),
    "uuid_multi_assign_smuggle": ("src/cfg2.py", ['request_id = "' + uuid() + '"; api_key = "' + uuid() + '"']),
}

# CLEAN: known-safe high-entropy values placed to produce ZERO findings.
#   - hash/uuid/sha values are whitelisted by the detector;
#   - keyword-bearing lines are put in non-source (.yaml/.lock) files or
#     comments, where P2 topic scoping does not fire -> no condition either.
_CLEAN = {
    "sha256_content_hash": ("src/bundle.py", ["content_hash = '" + sha256() + "'"]),
    "bare_git_commit_sha": ("src/version.py", ["commit = '" + sha256() + "'"]),
    "uuid_request_id": ("src/trace.py", ["request_id = '" + uuid() + "'"]),
    "lockfile_integrity": ("package-lock.yaml", ['  integrity: "sha512-' + _varied(40) + '"']),
    "placeholder_in_config": ("config/app.yaml", ['  api_key: "your-api-key-here"']),
    "password_word_in_comment": ("src/auth_doc.py", ["    # the password is read from the environment, never hardcoded"]),
}


def main() -> None:
    if _OUT.exists():
        shutil.rmtree(_OUT)
    for category, samples in (("vulnerable", _VULNERABLE), ("clean", _CLEAN)):
        d = _OUT / category
        d.mkdir(parents=True, exist_ok=True)
        for name, (path, added) in samples.items():
            (d / f"{name}.patch").write_text(_patch(path, added), encoding="utf-8")
    print(f"Wrote {len(_VULNERABLE)} vulnerable + {len(_CLEAN)} clean secrets samples to {_OUT}")


if __name__ == "__main__":
    main()
