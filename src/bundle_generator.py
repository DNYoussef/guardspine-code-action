"""

Bundle Generator - Creates cryptographically verifiable evidence bundles.

Primary output follows guardspine-spec v0.2.0. Legacy v1-style fields are
retained for backward compatibility with existing consumers/tests.
"""


import hashlib
import uuid
from base64 import b64encode
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
                "requires_approval": risk_result.get("risk_tier", "L2") in ("L3", "L4"),
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

        # Add signature if key provided
        if attestation_key:
            signature = self._sign_bundle(
                bundle,
                attestation_key,
                allow_insecure_fallback=allow_insecure_signature_fallback,
            )
            bundle["signatures"].append(signature)

        return bundle

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

            return {
                "signature_id": signature_id,
                "algorithm": algo,
                "signer_id": signer_id,
                "signature_value": signature_value,
                "signed_at": signed_at,
                "public_key_id": f"sha256:{public_fingerprint}",
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


def verify_bundle_chain(bundle: dict) -> tuple[bool, str]:
    """
    Verify the hash chain in a bundle.

    Returns:
        Tuple of (is_valid, message)
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

    return True, "Hash chain verified successfully"
