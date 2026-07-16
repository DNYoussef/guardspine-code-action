#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 GuardSpine, Inc.
# Licensed under the Business Source License 1.1. See LICENSE for terms.
# Change License: Apache-2.0. Change Date: see LICENSE.
"""
G-CODE-E2E independent local bundle verification.

The read-back gate (scripts/g_code_e2e_verify.py) trusts the GuardSpine
backend's own "verified: true" claim. This script does NOT trust the
backend at all: it re-derives the CI signing key's public half from the
SAME private key secret the action used, and calls the action's own
verify_bundle_chain() -- independent of the network -- against the bundle
file the action just wrote to disk, BEFORE the sync to prod. That recomputes
the hash chain (every item content_hash, the chain links, the root_hash, the
whole-bundle bundle_hash) and cryptographically verifies the signature
against the derived public key. Together with the backend read-back, this
gives two independent methods of the same claim: "this exact bundle,
untampered, was produced and signed by CI."

Usage:
    GUARDSPINE_ATTESTATION_KEY=<PEM private key> \\
        python scripts/verify_local_bundle_signature.py <bundle_path> <key_id>

<key_id> must be the same string passed to the action's attestation_key_id
input for this run (the value embedded in signature.public_key_id).

Depends on `cryptography` (already an action dependency -- see
requirements.txt) and reuses src/bundle_generator.verify_bundle_chain
rather than reimplementing hash-chain/signature verification.
"""
import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.bundle_generator import verify_bundle_chain  # noqa: E402


class LocalVerifyFailure(Exception):
    """One assertion failed. Message is the exact reason."""


def derive_public_key_pem(private_key_pem: str) -> str:
    """Derive the PEM-encoded public key from a PEM private key.

    Raises LocalVerifyFailure if the key cannot be loaded -- a bad/garbled
    secret must fail loud here, not produce a public key that can never
    match any signature.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
    except ImportError as exc:
        raise LocalVerifyFailure(f"cryptography library is not available: {exc}") from exc

    try:
        key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except Exception as exc:
        raise LocalVerifyFailure(f"could not load GUARDSPINE_ATTESTATION_KEY as a PEM private key: {exc}") from exc

    try:
        return key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    except Exception as exc:
        raise LocalVerifyFailure(f"could not derive public key: {exc}") from exc


def load_bundle(bundle_path: str) -> dict:
    path = Path(bundle_path)
    if not path.exists():
        raise LocalVerifyFailure(f"bundle file not found: {bundle_path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise LocalVerifyFailure(f"bundle file is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LocalVerifyFailure("bundle file does not contain a JSON object")
    return data


def verify_local_bundle(bundle_path: str, key_id: str, private_key_pem: str) -> str:
    """Independently verify the hash chain AND signature of a locally-saved
    bundle. Returns the success message; raises LocalVerifyFailure otherwise.
    """
    public_key_pem = derive_public_key_pem(private_key_pem)
    bundle = load_bundle(bundle_path)

    ok, message = verify_bundle_chain(
        bundle,
        trusted_keys={key_id: public_key_pem},
        require_signature=True,
    )
    if not ok:
        raise LocalVerifyFailure(message)
    return message


def main(argv: Optional[list[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("usage: verify_local_bundle_signature.py <bundle_path> <key_id>", file=sys.stderr)
        return 1
    bundle_path, key_id = argv

    if not key_id:
        print("::error::verify_local_bundle_signature: empty key_id")
        return 1

    import os
    private_key_pem = os.environ.get("GUARDSPINE_ATTESTATION_KEY", "")
    if not private_key_pem:
        print("::error::verify_local_bundle_signature: GUARDSPINE_ATTESTATION_KEY is not set")
        return 1

    try:
        message = verify_local_bundle(bundle_path, key_id, private_key_pem)
    except LocalVerifyFailure as exc:
        print(f"::error::verify_local_bundle_signature: {exc}")
        return 1

    print(f"verify_local_bundle_signature: PASS ({message})")
    print(f"  bundle_path: {bundle_path}")
    print(f"  key_id: {key_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
