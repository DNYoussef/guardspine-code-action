"""
PII-Shield integration spike.

Supports:
  - remote PII-Shield redaction/detection endpoint
  - provider findings ingestion for risk scoring
  - fail-open/fail-closed behavior
"""


import hashlib
import ipaddress
import json
import sys
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import requests


_LOOPBACK_HOSTNAMES = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
})


def _validate_endpoint(url: str) -> None:
    """Block SSRF-prone endpoints (cloud metadata, private IPs, loopback hostnames)."""
    import os
    import socket

    if os.environ.get("PII_SHIELD_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes"):
        return

    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"PII-Shield endpoint must use http(s): {url}")
    host = parsed.hostname or ""
    if host in ("169.254.169.254", "metadata.google.internal"):
        raise ValueError(f"PII-Shield endpoint cannot target cloud metadata: {url}")

    # Block known loopback hostnames
    if host.lower() in _LOOPBACK_HOSTNAMES:
        raise ValueError(f"PII-Shield endpoint cannot target localhost: {url}")

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback:
            raise ValueError(f"PII-Shield endpoint cannot target private IP: {url}")
    except ValueError as exc:
        if "cannot target" in str(exc):
            raise
        # Not an IP literal -- resolve hostname and check resolved address
        try:
            resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
            for _family, _type, _proto, _canonname, sockaddr in resolved:
                resolved_ip = ipaddress.ip_address(sockaddr[0])
                if resolved_ip.is_private or resolved_ip.is_loopback:
                    raise ValueError(
                        f"PII-Shield endpoint hostname resolves to private IP: {url}"
                    )
        except socket.gaierror:
            pass  # DNS failure -- request will fail naturally at call time


_HASH_FIELD_SUFFIXES = ("_hash",)
_HASH_FIELD_EXACT = frozenset({
    "signature_value", "public_key_id", "root_hash",
    "chain_hash", "previous_hash", "final_hash",
})


_DEFAULT_SAFE_REGEX_LIST = [
    {
        "pattern": "\\w+_hash[\"']?\\s*[:=]\\s*[\"']?(?:sha256:)?[0-9a-fA-F]{64}",
        "name": "HashFieldSHA256",
    },
    {
        "pattern": "^[0-9a-fA-F]{64}$",
        "name": "BareHexSHA256",
    },
]


def _is_hash_field(key: str) -> bool:
    return any(key.endswith(s) for s in _HASH_FIELD_SUFFIXES) or key in _HASH_FIELD_EXACT


def _extract_hash_fields(obj: Any, _prefix: str = "") -> dict[str, Any]:
    """Recursively extract hash/signature fields, returning {dotted_path: value}."""
    preserved: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            path = f"{_prefix}.{key}" if _prefix else key
            if _is_hash_field(key) and isinstance(obj[key], str):
                preserved[path] = obj.pop(key)
            elif isinstance(obj[key], (dict, list)):
                preserved.update(_extract_hash_fields(obj[key], path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                preserved.update(_extract_hash_fields(item, f"{_prefix}[{idx}]"))
    return preserved


def _reinject_hash_fields(obj: Any, preserved: dict[str, Any]) -> None:
    """Re-inject previously extracted hash fields at their original paths."""
    for path, value in preserved.items():
        _set_by_path(obj, path, value)


def _set_by_path(obj: Any, path: str, value: Any) -> None:
    """Set a value in a nested dict/list by dotted path with [n] indices."""
    parts: list[str] = []
    for segment in path.replace("[", ".[").split("."):
        if segment:
            parts.append(segment)
    cursor = obj
    for part in parts[:-1]:
        if part.startswith("[") and part.endswith("]"):
            cursor = cursor[int(part[1:-1])]
        else:
            cursor = cursor[part]
    last = parts[-1]
    if last.startswith("[") and last.endswith("]"):
        cursor[int(last[1:-1])] = value
    else:
        cursor[last] = value


class PIIShieldError(RuntimeError):
    """Raised when PII-Shield processing fails in fail-closed mode."""


@dataclass(frozen=True)
class PIIShieldResult:
    sanitized_text: str
    changed: bool
    redaction_count: int
    redactions_by_type: dict[str, int]
    mode: str
    provider: str
    input_hash: str
    output_hash: str
    signals: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "mode": self.mode,
            "provider": self.provider,
            "changed": self.changed,
            "redaction_count": self.redaction_count,
            "redactions_by_type": dict(self.redactions_by_type),
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "signal_count": len(self.signals),
            "details": dict(self.metadata),
        }

    def to_sensitive_zones(self) -> list[dict[str, Any]]:
        """Convert provider signals to RiskClassifier-sensitive zones."""
        zones: list[dict[str, Any]] = []
        for signal in self.signals:
            zones.append(
                {
                    "zone": signal.get("zone"),
                    "file": signal.get("file") or "__pii_shield__",
                    "line": signal.get("line"),
                    "content_preview": signal.get("content_preview", ""),
                    "detector": signal.get("detector", "pii_shield"),
                    "category": signal.get("category"),
                    "confidence": signal.get("confidence"),
                    "count": signal.get("count"),
                }
            )
        return zones


class PIIShieldClient:
    """PII-Shield integration client (provider-first)."""

    _VALID_MODES = {"auto", "local", "remote"}

    def __init__(
        self,
        enabled: bool = False,
        mode: str = "auto",
        endpoint: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float = 5.0,
        fail_closed: bool = True,
        salt_fingerprint: str = "sha256:00000000",
        safe_regex_list: str | None = None,
    ):
        self.enabled = enabled
        self.mode = (mode or "auto").strip().lower()
        self.endpoint = endpoint.strip() if endpoint else None
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.fail_closed = fail_closed
        self.salt_fingerprint = salt_fingerprint
        # PII-Shield v1.2.0+: JSON array of {"pattern": ..., "name": ...} objects
        # that bypass entropy detection entirely (replaces entropy threshold tuning).
        # Default: whitelist SHA-256 hex strings in _hash fields so that
        # content-addressable identifiers in evidence bundles are not flagged.
        self.safe_regex_list = safe_regex_list or json.dumps(
            _DEFAULT_SAFE_REGEX_LIST
        )

        if self.endpoint:
            _validate_endpoint(self.endpoint)

        if self.mode not in self._VALID_MODES:
            raise ValueError(
                f"Unsupported PII-Shield mode: {self.mode!r}. "
                f"Expected one of: {sorted(self._VALID_MODES)}"
            )

        if self.mode == "local":
            import warnings
            warnings.warn(
                "PII-Shield mode='local' is deprecated (identical to disabled). "
                "Use enabled=False or mode='auto' instead.",
                DeprecationWarning,
                stacklevel=2,
            )

    @staticmethod
    def _sha256(value: str) -> str:
        return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _with_extra_metadata(
        result: PIIShieldResult,
        extra: dict[str, Any],
    ) -> PIIShieldResult:
        metadata = dict(result.metadata)
        metadata.update(extra)
        return PIIShieldResult(
            sanitized_text=result.sanitized_text,
            changed=result.changed,
            redaction_count=result.redaction_count,
            redactions_by_type=dict(result.redactions_by_type),
            mode=result.mode,
            provider=result.provider,
            input_hash=result.input_hash,
            output_hash=result.output_hash,
            signals=list(result.signals),
            metadata=metadata,
        )

    def sanitize_text(
        self,
        text: str,
        input_format: str = "text",
        include_findings: bool = False,
        purpose: str | None = None,
    ) -> PIIShieldResult:
        """Sanitize text through PII-Shield according to configured mode."""
        input_hash = self._sha256(text)
        if not self.enabled:
            return PIIShieldResult(
                sanitized_text=text,
                changed=False,
                redaction_count=0,
                redactions_by_type={},
                mode="disabled",
                provider="none",
                input_hash=input_hash,
                output_hash=input_hash,
                signals=[],
                metadata={},
            )

        if self.mode == "remote" and not self.endpoint:
            if self.fail_closed:
                raise PIIShieldError("PII-Shield remote mode requires pii_shield_endpoint")
            return PIIShieldResult(
                sanitized_text=text,
                changed=False,
                redaction_count=0,
                redactions_by_type={},
                mode="remote",
                provider="passthrough",
                input_hash=input_hash,
                output_hash=input_hash,
                signals=[],
                metadata={"warning": "remote mode selected but pii_shield_endpoint is not configured"},
            )

        if self.mode in {"auto", "remote"} and self.endpoint:
            try:
                return self._sanitize_remote(
                    text=text,
                    input_format=input_format,
                    include_findings=include_findings,
                    purpose=purpose,
                )
            except Exception as exc:
                remote_error = str(exc)
                if self.mode == "remote" or self.fail_closed:
                    raise PIIShieldError(f"Remote PII-Shield failed: {exc}") from exc
                return PIIShieldResult(
                    sanitized_text=text,
                    changed=False,
                    redaction_count=0,
                    redactions_by_type={},
                    mode="auto",
                    provider="passthrough",
                    input_hash=input_hash,
                    output_hash=input_hash,
                    signals=[],
                    metadata={"warning": "remote PII-Shield failed; running fail-open passthrough", "remote_error": remote_error},
                )

        if self.mode == "local":
            # Kept only for compatibility; no built-in detector is implemented.
            print("::warning::PII-Shield local mode provides no PII detection. Configure a remote endpoint for actual protection.", file=sys.stderr)
            return PIIShieldResult(
                sanitized_text=text,
                changed=False,
                redaction_count=0,
                redactions_by_type={},
                mode="local",
                provider="passthrough",
                input_hash=input_hash,
                output_hash=input_hash,
                signals=[],
                metadata={"warning": "local mode is passthrough; configure remote endpoint for PII-Shield detection"},
            )

        return PIIShieldResult(
            sanitized_text=text,
            changed=False,
            redaction_count=0,
            redactions_by_type={},
            mode=self.mode,
            provider="passthrough",
            input_hash=input_hash,
            output_hash=input_hash,
            signals=[],
            metadata={"warning": "PII-Shield auto mode is passthrough without endpoint"},
        )

    def sanitize_diff(self, diff_content: str) -> PIIShieldResult:
        """Sanitize diff content and return redaction metadata + signals."""
        return self.sanitize_text(
            diff_content,
            input_format="diff",
            include_findings=True,
            purpose="diff",
        )

    def sanitize_json_document(
        self,
        document: Any,
        purpose: str = "json_document",
    ) -> tuple[Any, PIIShieldResult]:
        """
        Sanitize a JSON-like structure while preserving schema shape when possible.

        Hash and signature fields are extracted before sanitization and
        re-injected afterwards so that high-entropy cryptographic values
        are never sent to the remote PII-Shield endpoint.
        """
        import copy as _copy

        work = _copy.deepcopy(document) if isinstance(document, (dict, list)) else document
        preserved = _extract_hash_fields(work) if isinstance(work, (dict, list)) else {}

        original_json = json.dumps(
            work,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        result = self.sanitize_text(
            original_json,
            input_format="json",
            include_findings=False,
            purpose=purpose,
        )
        if not result.changed:
            if preserved:
                _reinject_hash_fields(work, preserved)
            return work if preserved else document, result

        try:
            sanitized_document = json.loads(result.sanitized_text)
            if preserved:
                _reinject_hash_fields(sanitized_document, preserved)
            return sanitized_document, result
        except json.JSONDecodeError as exc:
            if self.fail_closed:
                raise PIIShieldError(
                    f"PII-Shield returned non-JSON sanitized content for {purpose}: {exc}"
                ) from exc
            enriched = self._with_extra_metadata(
                result,
                {
                    "parse_error": str(exc),
                    "warning": f"sanitized {purpose} content was not valid JSON; fail-open passthrough",
                },
            )
            if preserved:
                _reinject_hash_fields(document, preserved)
            return document, enriched

    def _sanitize_remote(
        self,
        text: str,
        input_format: str,
        include_findings: bool,
        purpose: str | None,
    ) -> PIIShieldResult:
        if self.endpoint and self.endpoint.lower().startswith("http"):
            return self._sanitize_via_http(text, input_format, include_findings, purpose)
        return self._sanitize_via_wasm(text, input_format, include_findings, purpose)

    def _sanitize_via_http(
        self,
        text: str,
        input_format: str,
        include_findings: bool,
        purpose: str | None,
    ) -> PIIShieldResult:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "text": text,
            "input_format": input_format,
            "deterministic": True,
            "preserve_line_numbers": True,
            "include_findings": include_findings,
            "salt_fingerprint": self.salt_fingerprint,
        }
        if self.safe_regex_list:
            try:
                parsed = json.loads(self.safe_regex_list)
                if isinstance(parsed, list):
                    payload["safe_regex_list"] = parsed
            except (json.JSONDecodeError, TypeError):
                pass  # Invalid JSON -- skip, PII-Shield will use its own defaults
        if purpose:
            payload["purpose"] = purpose

        response = requests.post(
            self.endpoint,
            json=payload,
            headers=headers,
            timeout=self.timeout_seconds,
            allow_redirects=False,
        )
        if 300 <= response.status_code < 400:
            raise ValueError("PII-Shield endpoint redirects are not allowed")
        response.raise_for_status()
        body = response.json()

        sanitized = (
            body.get("sanitized_text")
            or body.get("redacted_text")
            or body.get("text")
            or body.get("output")
        )
        if not isinstance(sanitized, str):
            raise ValueError("Remote PII-Shield response did not include sanitized text")

        redactions_by_type = self._extract_redactions_by_type(body)
        redaction_count = body.get("redaction_count")
        if not isinstance(redaction_count, int):
            redaction_count = sum(redactions_by_type.values())
            if redaction_count == 0 and isinstance(body.get("redactions"), list):
                redaction_count = len(body["redactions"])
        redaction_count = max(0, redaction_count)

        signals = self._extract_signals(body, redactions_by_type)

        return PIIShieldResult(
            sanitized_text=sanitized,
            changed=(sanitized != text),
            redaction_count=redaction_count,
            redactions_by_type=redactions_by_type,
            mode="remote",
            provider=body.get("provider", "pii-shield-remote"),
            input_hash=self._sha256(text),
            output_hash=self._sha256(sanitized),
            signals=signals,
            metadata={
                "status_code": response.status_code,
                "schema_version": body.get("schema_version"),
                "engine_version": body.get("engine_version") or body.get("version"),
                "model": body.get("model"),
                "input_format": input_format,
            },
        )

    def _sanitize_via_wasm(
        self,
        text: str,
        input_format: str,
        include_findings: bool,
        purpose: str | None,
    ) -> PIIShieldResult:
        # WASM Integration: Use local WASM client instead of HTTP
        try:
            from .adapters.pii_wasm_client import PIIWasmClient
        except ImportError:
            # Fallback for when running without package context (e.g. local tests)
            from adapters.pii_wasm_client import PIIWasmClient
        
        client = PIIWasmClient()
        # Note: WASM client currently only supports text redaction (ScanAndRedact)
        # It does not yet support structured findings or config override via arguments in the same way 
        # as the HTTP API (payload).
        # However, for "The Leak Test", we primarily need redaction.
        
        # TODO: Pass configuration (safe_regex_list, etc) to WASM if not already handled by ENV vars.
        # The current WASM implementation relies on ENV vars read by the Go process.
        
        try:
            sanitized = client.redact(text)
        except Exception as exc:
             raise RuntimeError(f"WASM PII-Shield failed: {exc}") from exc

        # Mocking the rich response structure of the HTTP API for compatibility
        # iterating over the redacted string to check if it changed
        changed = (sanitized != text)
        redaction_count = 0
        if changed:
            # Simple heuristic since WASM doesn't return count yet
            redaction_count = sanitized.count("[HIDDEN")
            
        return PIIShieldResult(
            sanitized_text=sanitized,
            changed=changed,
            redaction_count=redaction_count,
            redactions_by_type={}, # WASM simple output doesn't provide this yet
            mode="wasm-local",
            provider="pii-shield-wasm",
            input_hash=self._sha256(text),
            output_hash=self._sha256(sanitized),
            signals=[], # WASM simple output doesn't provide signals yet
            metadata={
                "input_format": input_format,
                "engine": "wasm",
            },
        )

    @staticmethod
    def _extract_redactions_by_type(body: dict[str, Any]) -> dict[str, int]:
        raw = body.get("redactions_by_type")
        if isinstance(raw, dict):
            clean: dict[str, int] = {}
            for key, value in raw.items():
                try:
                    clean[str(key)] = int(value)
                except (TypeError, ValueError):
                    continue
            return clean

        redactions = body.get("redactions")
        if isinstance(redactions, list):
            counts: dict[str, int] = {}
            for item in redactions:
                label = "unknown"
                if isinstance(item, dict):
                    label = str(
                        item.get("type")
                        or item.get("category")
                        or item.get("label")
                        or "unknown"
                    )
                counts[label] = counts.get(label, 0) + 1
            return counts

        return {}

    @staticmethod
    def _map_label_to_zone(label: str) -> str | None:
        normalized = (label or "").strip().lower().replace("-", "_").replace(" ", "_")
        if not normalized:
            return None
        parts = set(normalized.split("_"))
        if any(k in parts for k in ("email", "phone", "ssn", "pii", "phi", "personal")):
            return "pii"
        if any(k in parts for k in ("card", "pan", "payment", "billing")):
            return "payment"
        if any(k in parts for k in ("secret", "token", "credential", "password", "key", "entropy")):
            return "entropy_secret"
        return None

    @staticmethod
    def _as_int(value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _extract_signals(
        self,
        body: dict[str, Any],
        redactions_by_type: dict[str, int],
    ) -> list[dict[str, Any]]:
        raw_signals = (
            body.get("detections")
            or body.get("findings")
            or body.get("matches")
            or body.get("redactions")
            or []
        )

        signals: list[dict[str, Any]] = []
        if isinstance(raw_signals, list):
            for item in raw_signals:
                if not isinstance(item, dict):
                    continue
                label = str(
                    item.get("type")
                    or item.get("category")
                    or item.get("label")
                    or item.get("name")
                    or "unknown"
                )
                zone = self._map_label_to_zone(label)
                if not zone:
                    continue
                line = (
                    self._as_int(item.get("line"))
                    or self._as_int(item.get("line_number"))
                    or self._as_int(item.get("start_line"))
                )
                signal = {
                    "zone": zone,
                    "file": str(item.get("file") or item.get("path") or "__pii_shield__"),
                    "line": line,
                    "detector": "pii_shield",
                    "category": label,
                    "content_preview": str(
                        item.get("text")
                        or item.get("value")
                        or item.get("token")
                        or ""
                    )[:120],
                }
                confidence = item.get("confidence")
                try:
                    if confidence is not None:
                        signal["confidence"] = float(confidence)
                except (TypeError, ValueError):
                    pass
                signals.append(signal)

        if not signals:
            for label, count in redactions_by_type.items():
                zone = self._map_label_to_zone(label)
                if not zone:
                    continue
                signals.append(
                    {
                        "zone": zone,
                        "file": "__pii_shield__",
                        "line": None,
                        "detector": "pii_shield",
                        "category": label,
                        "count": int(count),
                        "content_preview": "",
                    }
                )

        deduped: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for signal in signals:
            key = (
                signal.get("zone"),
                signal.get("file"),
                signal.get("line"),
                signal.get("category"),
                signal.get("content_preview"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(signal)
        return deduped
