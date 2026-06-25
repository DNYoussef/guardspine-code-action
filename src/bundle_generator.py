# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 GuardSpine, Inc.
# Licensed under the Business Source License 1.1. See LICENSE for terms.
# Change License: Apache-2.0. Change Date: see LICENSE.
"""
Bundle Generator - Creates cryptographically verifiable evidence bundles.

Primary output follows guardspine-spec v0.2.0. Legacy v1-style fields are
retained for backward compatibility with existing consumers/tests.
"""

from __future__ import annotations

import hashlib
import uuid
from base64 import b64encode, b64decode
from datetime import datetime, timezone
from typing import Any, Optional, TYPE_CHECKING
from dataclasses import dataclass, field

from github.PullRequest import PullRequest

if TYPE_CHECKING:
    from .analyzer import AnalysisResult

try:
    from .canonical_json import canonical_json_dumps
except ImportError:  # pragma: no cover - fallback for direct module imports in tests
    from canonical_json import canonical_json_dumps


@dataclass
class BundleEvent:
    """A single event in the evidence chain."""
    event_type: str
    timestamp: str
    actor: str
    data: dict
    hash: str = ""

    def compute_hash(self, previous_hash: str = "") -> str:
        """Compute hash for this event including previous hash."""
        content = canonical_json_dumps(
            {
                "event_type": self.event_type,
                "timestamp": self.timestamp,
                "actor": self.actor,
                "data": self.data,
                "previous_hash": previous_hash,
            }
        )
        self.hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return self.hash


class BundleGenerator:
    """
    Generates evidence bundles with a v0.2.0 canonical immutability proof.
    Legacy event/hash_chain fields are also emitted for compatibility.

    Bundle structure:
    - Header: version, bundle_id, timestamps, context
    - Events: Hash-chained sequence of actions
    - Summary: Risk tier, findings, rationale
    - Signatures: Cryptographic attestations (optional)
    """

    SPEC_VERSION = "0.2.0"

    def __init__(self):
        """Initialize bundle generator."""
        self.events: list[BundleEvent] = []

    def create_bundle(
        self,
        pr: PullRequest,
        analysis: AnalysisResult | dict[str, Any],
        risk_result: dict[str, Any],
        repository: str,
        commit_sha: str,
        approvers: list[str] = None,
        attestation_key: Optional[str] = None,
        allow_insecure_signature_fallback: bool = False,
    ) -> dict[str, Any]:
        """
        Create a complete evidence bundle for a PR.

        Args:
            pr: GitHub PullRequest object
            analysis: Analysis results from DiffAnalyzer
            risk_result: Classification from RiskClassifier
            repository: Repository name (owner/repo)
            commit_sha: Commit SHA being analyzed
            approvers: List of approver usernames (optional)
            attestation_key: Private key for signing (optional)

        Returns:
            Complete evidence bundle as dict
        """
        bundle_id = self._generate_bundle_id(repository, pr.number, commit_sha)
        created_at = datetime.now(timezone.utc).isoformat()

        # Build event chain
        self.events = []
        previous_hash = ""

        # Event 1: PR Created/Updated
        pr_event = BundleEvent(
            event_type="pr_submitted",
            timestamp=pr.created_at.isoformat() if pr.created_at else created_at,
            actor=pr.user.login if pr.user else "unknown",
            data={
                "pr_number": pr.number,
                "title": pr.title,
                "base_branch": pr.base.ref if pr.base else "main",
                "head_branch": pr.head.ref if pr.head else "unknown",
                "head_sha": commit_sha,
            }
        )
        previous_hash = pr_event.compute_hash(previous_hash)
        self.events.append(pr_event)

        raw_diff_hash = analysis.get("raw_diff_hash", analysis.get("diff_hash", ""))
        analysis_diff_hash = analysis.get("ai_diff_hash", analysis.get("diff_hash", ""))
        pii_shield = analysis.get("pii_shield", {"enabled": False})
        sanitization = analysis.get("sanitization")

        # Extract per-model provenance for sealing into the hash chain.
        mmr = analysis.get("multi_model_review") or {}
        reviews_sealed = [
            {
                "model_name": r.get("model_name", ""),
                "provider": r.get("provider", ""),
                "model_id": r.get("model_id", r.get("model_name", "")),
                "prompt_hash": r.get("prompt_hash", ""),
                "response_hash": r.get("response_hash", ""),
            }
            for r in (mmr.get("reviews") or [])
            if not r.get("error")
        ]

        # Event 2: Analysis Completed
        analysis_event = BundleEvent(
            event_type="analysis_completed",
            timestamp=created_at,
            actor="guardspine-codeguard",
            data={
                "files_changed": analysis.get("files_changed", 0),
                "lines_added": analysis.get("lines_added", 0),
                "lines_removed": analysis.get("lines_removed", 0),
                "sensitive_zones_count": len(analysis.get("sensitive_zones", [])),
                "diff_hash": analysis.get("diff_hash", ""),
                "raw_diff_hash": raw_diff_hash,
                "analysis_diff_hash": analysis_diff_hash,
                "pii_shield": pii_shield,
                "sanitization": sanitization,
                "reviews_sealed": reviews_sealed,
            }
        )
        previous_hash = analysis_event.compute_hash(previous_hash)
        self.events.append(analysis_event)

        # Event 3: Risk Classification
        risk_event = BundleEvent(
            event_type="risk_classified",
            timestamp=created_at,
            actor="guardspine-codeguard",
            data={
                "risk_tier": risk_result.get("risk_tier", "L2"),
                "findings_count": len(risk_result.get("findings", [])),
                "scores": risk_result.get("scores", {}),
            }
        )
        previous_hash = risk_event.compute_hash(previous_hash)
        self.events.append(risk_event)

        # Event 4: Approval (if approvers provided)
        if approvers:
            for approver in approvers:
                approval_event = BundleEvent(
                    event_type="approval_granted",
                    timestamp=created_at,
                    actor=approver,
                    data={
                        "risk_tier_at_approval": risk_result.get("risk_tier", "L2"),
                        "commit_sha": commit_sha,
                    }
                )
                previous_hash = approval_event.compute_hash(previous_hash)
                self.events.append(approval_event)

        # Build complete bundle
        v020_items = self._build_v020_items()
        v020_proof = self._build_v020_proof(v020_items)

        bundle = {
            "version": self.SPEC_VERSION,
            "guardspine_spec_version": self.SPEC_VERSION,
            "bundle_id": bundle_id,
            "created_at": created_at,
            "context": {
                "repository": repository,
                "pr_number": pr.number,
                "commit_sha": commit_sha,
                "base_branch": pr.base.ref if pr.base else "main",
                "head_branch": pr.head.ref if pr.head else "unknown",
            },
            # DEPRECATED: legacy fields retained for backward compatibility.
            # Consumers should use 'items' + 'immutability_proof' instead.
            # These fields will be removed in the next major version.
            "events": [self._event_to_dict(e) for e in self.events],
            "hash_chain": {
                "algorithm": "sha256",
                "final_hash": previous_hash,
                "event_count": len(self.events),
            },
            "items": v020_items,
            "immutability_proof": v020_proof,
            "summary": {
                "risk_tier": risk_result.get("risk_tier", "L2"),
                "risk_drivers": risk_result.get("risk_drivers", []),
                "findings": risk_result.get("findings", []),
                "rationale": risk_result.get("rationale", ""),
                "requires_approval": risk_result.get(
                    "requires_approval",
                    risk_result.get("risk_tier", "L2") in ("L3", "L4"),
                ),
                "decision": risk_result.get("decision", "merge"),
            },
            "sanitization": sanitization,
            "analysis_snapshot": {
                "files_changed": analysis.get("files_changed", 0),
                "lines_added": analysis.get("lines_added", 0),
                "lines_removed": analysis.get("lines_removed", 0),
                "sensitive_zones": self._summarize_zones(analysis.get("sensitive_zones", [])),
                "ai_summary": analysis.get("ai_summary", {}),
                "multi_model_review": self._redact_review(analysis.get("multi_model_review") or {}),
                "preliminary_tier": analysis.get("preliminary_tier", ""),
                "models_used": analysis.get("models_used", 0),
                "models_failed": analysis.get("models_failed", 0),
                "model_errors": analysis.get("model_errors", []),
                "raw_diff_hash": raw_diff_hash,
                "analysis_diff_hash": analysis_diff_hash,
                "pii_shield": pii_shield,
                "sanitization": sanitization,
            },
            "signatures": [],
        }

        # Seal as the final step: whole-bundle hash + optional signature.
        self.seal_bundle(
            bundle,
            attestation_key=attestation_key,
            allow_insecure_signature_fallback=allow_insecure_signature_fallback,
        )
        return bundle

    def seal_bundle(
        self,
        bundle: dict,
        attestation_key: str | None = None,
        allow_insecure_signature_fallback: bool = False,
        strip_signatures: bool = False,
    ) -> dict:
        """Stamp the whole-bundle hash (and optionally sign). MUST be the LAST
        thing done to a bundle: any mutation afterwards invalidates the seal.
        If a bundle is mutated after create_bundle (e.g. post-hoc PII
        sanitization), call this again to re-seal the final bytes -- otherwise
        the saved artifact fails its own verify_bundle_chain.

        If the bundle already carries signatures, re-sealing would invalidate them
        (the payload changed). Pass attestation_key to RE-SIGN, or strip_signatures=
        True to deliberately drop them -- otherwise this raises rather than silently
        discarding a real signature.
        """
        if bundle.get("signatures") and not attestation_key and not strip_signatures:
            raise ValueError(
                "seal_bundle would drop existing signatures: pass attestation_key "
                "to re-sign, or strip_signatures=True to drop them deliberately"
            )
        # Re-sign from scratch: a stale signature over pre-mutation bytes is invalid.
        bundle["signatures"] = []
        # Keyless whole-bundle seal: any byte change in ANY field changes this.
        # Covers summary/analysis_snapshot/context/sanitization, which the
        # per-item root_hash does not. Recomputable by anyone -- tamper-evidence,
        # not non-repudiation (that still needs an attestation_key).
        bundle["bundle_hash"] = self._compute_bundle_hash(bundle)
        if attestation_key:
            bundle["signatures"].append(
                self._sign_bundle(
                    bundle,
                    attestation_key,
                    allow_insecure_fallback=allow_insecure_signature_fallback,
                )
            )
        return bundle

    @staticmethod
    def _compute_bundle_hash(bundle: dict) -> str:
        """SHA-256 over the canonical bundle, excluding the digest + signatures.

        Recomputable by anyone, so altering any top-level field (summary,
        analysis_snapshot, context, ...) is detectable -- not just the items the
        root_hash already chains. Stays "hash-chained, not signed": keyless.
        """
        payload = {k: v for k, v in bundle.items()
                   if k not in ("bundle_hash", "signatures")}
        canonical = canonical_json_dumps(payload).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def _generate_bundle_id(self, repository: str, pr_number: int, commit_sha: str) -> str:
        """Generate a deterministic UUID v5 bundle ID from inputs."""
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{repository}/pull/{pr_number}/{commit_sha}"))

    def _event_to_dict(self, event: BundleEvent) -> dict:
        """Convert BundleEvent to dict."""
        return {
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "actor": event.actor,
            "data": event.data,
            "hash": event.hash,
        }

    def _summarize_zones(self, zones: list) -> dict:
        """Summarize sensitive zones by type."""
        summary = {}
        for zone in zones:
            zone_type = zone.get("zone", "unknown")
            if zone_type not in summary:
                summary[zone_type] = {"count": 0, "files": set()}
            summary[zone_type]["count"] += 1
            summary[zone_type]["files"].add(zone.get("file", "unknown"))

        # Convert sets to lists for JSON serialization
        for zone_type in summary:
            summary[zone_type]["files"] = sorted(summary[zone_type]["files"])

        return summary

    @staticmethod
    def _redact_review(mmr: dict) -> dict:
        """Strip raw_response from review dicts to avoid leaking diff content."""
        if not mmr:
            return mmr
        redacted = dict(mmr)
        reviews = redacted.get("reviews")
        if isinstance(reviews, list):
            redacted["reviews"] = [
                {k: v for k, v in r.items() if k != "raw_response"}
                for r in reviews
            ]
        return redacted

    def _build_v020_items(self) -> list[dict[str, Any]]:
        """Map legacy events into v0.2.0 bundle item records."""
        items: list[dict[str, Any]] = []
        for idx, event in enumerate(self.events):
            content = {
                "event_type": event.event_type,
                "timestamp": event.timestamp,
                "actor": event.actor,
                "data": event.data,
            }
            serialized = canonical_json_dumps(content)
            content_hash = "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            items.append({
                "item_id": f"event-{idx:04d}",
                "sequence": idx,
                "content_type": f"guardspine/codeguard/{event.event_type}",
                "content": content,
                "content_hash": content_hash,
            })
        return items

    def _build_v020_proof(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        """Build a v0.2.0 immutability proof from item records."""
        hash_chain: list[dict[str, Any]] = []
        previous_hash = "genesis"
        for item in items:
            sequence = item["sequence"]
            chain_input = (
                f"{sequence}|{item['item_id']}|{item['content_type']}|"
                f"{item['content_hash']}|{previous_hash}"
            )
            chain_hash = "sha256:" + hashlib.sha256(chain_input.encode()).hexdigest()
            hash_chain.append({
                "sequence": sequence,
                "item_id": item["item_id"],
                "content_type": item["content_type"],
                "content_hash": item["content_hash"],
                "previous_hash": previous_hash,
                "chain_hash": chain_hash,
            })
            previous_hash = chain_hash

        h = hashlib.sha256()
        for link in hash_chain:
            h.update(link["chain_hash"].encode("utf-8"))
        root_hash = "sha256:" + h.hexdigest()
        return {
            "hash_chain": hash_chain,
            "root_hash": root_hash,
        }

    def _sign_bundle(
        self,
        bundle: dict,
        private_key: str,
        allow_insecure_fallback: bool = False,
    ) -> dict:
        """
        Sign bundle with the provided private key.

        Supports PEM-encoded Ed25519, RSA, or EC keys when cryptography is
        available. Falls back to HMAC-SHA256 if cryptography is unavailable.
        """
        signed_at = datetime.now(timezone.utc).isoformat()
        signature_id = str(uuid.uuid4())
        signer_id = "guardspine-codeguard"

        # Sign the full bundle payload excluding signatures.
        signing_payload = {k: v for k, v in bundle.items() if k != "signatures"}
        canonical = canonical_json_dumps(signing_payload)
        canonical_bytes = canonical.encode("utf-8")

        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, ec
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            key = load_pem_private_key(private_key.encode(), password=None)

            if isinstance(key, ed25519.Ed25519PrivateKey):
                signature = key.sign(canonical_bytes)
                algo = "ed25519"
            elif isinstance(key, rsa.RSAPrivateKey):
                signature = key.sign(
                    canonical_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                algo = "rsa-sha256"
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                if key.curve.name.lower() != "secp256r1":
                    raise ValueError("Unsupported ECDSA curve; required: secp256r1 (P-256)")
                signature = key.sign(
                    canonical_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
                algo = "ecdsa-p256"
            else:
                raise ValueError("Unsupported key type for signing")

            public_key_bytes = key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
            signature_value = b64encode(signature).decode()
            public_key_pem = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()

            return {
                "signature_id": signature_id,
                "algorithm": algo,
                "signer_id": signer_id,
                "signature_value": signature_value,
                "signed_at": signed_at,
                "public_key_id": f"sha256:{public_fingerprint}",
                # Embed the public key so bundles are self-contained: a verifier
                # can check the signature AND pin the fingerprint without a side
                # channel. Trust still requires the fingerprint to be allow-listed
                # by the verifier -- the embedded key is NEVER trusted on its own.
                "public_key": public_key_pem,
            }
        except ImportError as exc:
            if not allow_insecure_fallback:
                raise ValueError(
                    "cryptography library is required for strict signature mode"
                ) from exc
            import hmac
            signature = hmac.new(private_key.encode(), canonical_bytes, hashlib.sha256).digest()
            return {
                "signature_id": signature_id,
                "algorithm": "hmac-sha256",
                "signer_id": signer_id,
                "signature_value": b64encode(signature).decode(),
                "signed_at": signed_at,
                "note": "cryptography library not available; used HMAC-SHA256",
            }
        except Exception as exc:
            if not allow_insecure_fallback:
                raise ValueError(f"Invalid signing key: {exc}") from exc
            import hmac
            signature = hmac.new(private_key.encode(), canonical_bytes, hashlib.sha256).digest()
            return {
                "signature_id": signature_id,
                "algorithm": "hmac-sha256",
                "signer_id": signer_id,
                "signature_value": b64encode(signature).decode(),
                "signed_at": signed_at,
                "note": f"key parsing failed; used HMAC-SHA256 instead: {exc}",
            }


def _load_public_key_der(key_source: str):
    """Load a PEM/DER-b64 public key; return (key_obj, der_spki_bytes). Raises on bad key."""
    from cryptography.hazmat.primitives import serialization
    data = key_source.encode() if isinstance(key_source, str) else key_source
    if b"BEGIN" in data:
        key = serialization.load_pem_public_key(data)
    else:
        key = serialization.load_der_public_key(b64decode(key_source, validate=True))
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, der


def _verify_asym(algo: str, public_key, signature: bytes, content: bytes) -> bool:
    """True iff `signature` is a valid `algo` signature over `content`. Fail-closed."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, ec
        if algo == "ed25519" and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, content)
        elif algo == "rsa-sha256" and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, content, padding.PKCS1v15(), hashes.SHA256())
        elif algo == "ecdsa-p256" and isinstance(public_key, ec.EllipticCurvePublicKey):
            if public_key.curve.name.lower() != "secp256r1":
                return False
            public_key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except Exception:
        return False


def _count_trusted_valid_signatures(bundle: dict, trusted_fingerprints, trusted_keys) -> int:
    """Count asymmetric signatures that are BOTH cryptographically valid over the
    canonical payload AND trusted. Trust = the signer key's RECOMPUTED fingerprint
    is allow-listed (embedded-key path) OR its key_id is in trusted_keys (external
    path, verified against the CALLER's key). HMAC never counts (shared secret)."""
    sigs = bundle.get("signatures") or []
    # Fail closed on malformed input: a non-list signatures value, or non-dict
    # elements, must mean "no trusted signatures", never a crash (red-team nit).
    if not isinstance(sigs, list) or not sigs:
        return 0
    if len(sigs) > 1000:        # absurd count -> fail closed (DoS guard)
        return 0
    content = canonical_json_dumps(
        {k: v for k, v in bundle.items() if k != "signatures"}).encode("utf-8")
    tf = set(trusted_fingerprints or [])
    tk = dict(trusted_keys or {})
    # Trust is checked (cheap) BEFORE the expensive crypto verify, and we
    # short-circuit on the first trusted+valid signature -- so junk/untrusted
    # signatures (any order, up to the cap) cannot starve a real one.
    for sig in sigs:
        if not isinstance(sig, dict):
            continue
        if sig.get("algorithm") not in ("ed25519", "rsa-sha256", "ecdsa-p256"):
            continue  # hmac / unknown: not anti-forgery
        sigval = sig.get("signature_value")
        if not sigval:
            continue
        key_id = sig.get("public_key_id")
        # External trust: caller explicitly supplied this key_id -> use THEIR key
        # (an attacker's embedded key is ignored on this path).
        if key_id and key_id in tk:
            key_source, trusted = tk[key_id], True
        elif sig.get("public_key"):
            key_source, trusted = sig["public_key"], False  # embedded: must pin below
        else:
            continue
        try:
            pub, der = _load_public_key_der(key_source)
        except Exception:
            continue
        # Recompute fingerprint from the ACTUAL key bytes -- never trust the claimed
        # public_key_id field (defeats key_id spoofing).
        if not trusted:
            if ("sha256:" + hashlib.sha256(der).hexdigest()) not in tf:
                continue
        try:
            sigbytes = b64decode(sigval, validate=True)
        except Exception:
            continue
        if _verify_asym(sig.get("algorithm"), pub, sigbytes, content):
            return 1   # one trusted, valid signature is sufficient
    return 0


def verify_bundle_chain(
    bundle: dict,
    trusted_fingerprints=None,
    trusted_keys: dict | None = None,
    require_signature: bool = False,
) -> tuple[bool, str]:
    """
    Verify a bundle. Two tiers:
      * integrity (default): event chain + whole-bundle bundle_hash (tamper-EVIDENT).
      * anti-forgery (opt-in): pass trusted_fingerprints (allow-listed "sha256:..."
        of producer public keys), and/or trusted_keys ({key_id: PEM}), and/or
        require_signature=True. The bundle then needs >=1 asymmetric signature that
        is cryptographically valid over canonical_json(bundle - signatures) AND
        trusted (signer fingerprint allow-listed, or key_id in trusted_keys). HMAC
        is never anti-forgery.

    Returns: (is_valid, message)
    """
    events = bundle.get("events", [])
    if not events:
        return False, "No events in bundle"

    previous_hash = ""
    for i, event in enumerate(events):
        # Recompute hash
        content = canonical_json_dumps(
            {
                "event_type": event["event_type"],
                "timestamp": event["timestamp"],
                "actor": event["actor"],
                "data": event["data"],
                "previous_hash": previous_hash,
            }
        )
        computed_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        if computed_hash != event["hash"]:
            return False, f"Hash mismatch at event {i}: expected {event['hash']}, got {computed_hash}"

        previous_hash = computed_hash

    # Verify final hash
    final_hash = bundle.get("hash_chain", {}).get("final_hash", "")
    if previous_hash != final_hash:
        return False, f"Final hash mismatch: expected {final_hash}, got {previous_hash}"

    # Whole-bundle seal. A MODERN bundle (declares a 0.2.x version/spec, or carries
    # items/immutability_proof) MUST be sealed with bundle_hash -- refusing the
    # event-only fallback closes the downgrade bypass (strip bundle_hash AND
    # immutability_proof). Only a bundle with NONE of those modern markers is treated
    # as genuinely legacy and verified on the event chain alone.
    expected_bundle_hash = bundle.get("bundle_hash")
    # A bundle carrying ANY field that bundle_hash is meant to protect MUST be
    # sealed. You cannot keep a forgeable rich field (summary, analysis_snapshot,
    # items, ...) without bundle_hash -- so stripping every version/items marker
    # does not buy a downgrade as long as the forged field itself is present. Only
    # a bare event-only legacy bundle (none of these fields) verifies on the event
    # chain alone.
    _rich = ("items", "immutability_proof", "summary", "analysis_snapshot",
             "context", "sanitization")
    requires_seal = (
        str(bundle.get("version", "")).startswith("0.2")
        or str(bundle.get("guardspine_spec_version", "")).startswith("0.2")
        or any(f in bundle for f in _rich)   # PRESENCE, not truthiness: a present-but-empty rich field still requires the seal
    )
    if requires_seal and not expected_bundle_hash:
        return False, "missing bundle_hash: a sealed-class bundle is not sealed (downgrade)"
    if expected_bundle_hash:
        recomputed = BundleGenerator._compute_bundle_hash(bundle)
        if recomputed != expected_bundle_hash:
            return False, (
                "bundle_hash mismatch: a top-level field was altered "
                f"(expected {expected_bundle_hash}, got {recomputed})"
            )

    # Anti-forgery tier: any trust anchor (trusted_fingerprints/trusted_keys) OR
    # require_signature activates the signature gate -- the bundle then needs >=1
    # cryptographically valid signature from a trusted key.
    if require_signature or trusted_fingerprints or trusted_keys:
        if _count_trusted_valid_signatures(
                bundle, trusted_fingerprints, trusted_keys) == 0:
            return False, (
                "no valid signature from a trusted key "
                "(absent, untrusted, forged, or HMAC-only)"
            )

    return True, "Hash chain verified successfully"
