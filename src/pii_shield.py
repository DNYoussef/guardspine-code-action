"""
PII-Shield integration. IN-PROCESS ONLY -- there is no HTTP client.

Redaction runs locally through the published `pii-shield-wasi` package.
Nothing in this module makes a network request, and that is the point:
three rounds of hardening once went into defending an outbound call --
SSRF validation, cloud-metadata blocking, connect-time DNS-rebind pinning
-- and removing the call removes that entire class. A request that is
never made has no SSRF surface, no rebinding surface, and no API key to
leak in a header.

How the old shape hid the safe path, recorded because it is the reason
this change was needed rather than merely nice. `_sanitize_remote`
dispatched on `endpoint.lower().startswith("http")`: HTTP when the value
looked like a URL, WASM otherwise -- and action.yml documents that field
as "Optional PII-Shield HTTP endpoint". So the in-process path was
reachable only by putting a non-http value into a field documented as
http. Worse, sanitization ran only when an endpoint was set, so with the
field empty PII-Shield did nothing at all.

Now: no endpoint is required or used, and sanitization happens whenever
the shield is enabled.

WHAT THE ENGINE DOES NOT PROVIDE, and how that gap is closed. The old
HTTP API returned structured findings and metadata; the package exposes
`redact(str) -> str`. An earlier version of this docstring claimed the
richer fields had no consumer ("analyzer.py builds sensitive_zones from
its own analysis"). That claim was checked and found WRONG: entrypoint.py
merges `to_sensitive_zones()` into the analysis and the RiskClassifier
scores those zones into the risk tier, so shipping empty signals silently
removed PII from risk scoring while the pipeline still appeared to score
it. The fix is local reconstruction: input and redacted output are
compared line by line, and each changed line becomes a zone carrying a
line number and a count -- never the matched text. What this does NOT
recover is categories: the engine reports none, so every reconstructed
zone is the single constant "pii" and `redactions_by_type` stays empty.
If per-category findings are wanted later they come from upstream, not
from re-adding a network call.
"""


import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any


def _load_wasm_engine():
    """Import the installed pii-shield-wasi package, not ourselves.

    THIS FILE IS ALSO CALLED pii_shield.py. Whenever src/ is on sys.path
    -- which it is in several entrypoint layouts, and in the existing test
    suite -- a bare `import pii_shield` binds to THIS module. A plain
    import therefore either explodes with "not a package" or, in a
    slightly different layout, silently returns the wrong thing, which is
    far worse: sanitization would appear configured and do nothing.

    So the directory containing this file is removed from sys.path for the
    duration of the import and restored immediately after. Deterministic,
    and it cannot resolve to us.
    """
    import importlib
    import sys as _sys

    here = os.path.dirname(os.path.abspath(__file__))
    saved_path = list(_sys.path)
    saved_module = _sys.modules.pop("pii_shield", None)
    try:
        _sys.path = [p for p in _sys.path
                     if os.path.abspath(p or os.getcwd()) != here]
        scanner = importlib.import_module("pii_shield.scanner")
        return scanner.PiiShield, scanner.PiiShieldConfig
    finally:
        _sys.path = saved_path
        # Put our own module back exactly as it was: leaving the package
        # bound under this name would shadow US for every later import.
        if saved_module is not None:
            _sys.modules["pii_shield"] = saved_module
        else:
            _sys.modules.pop("pii_shield", None)


# Retained from the pre-WASM module: these are the hash-field whitelist
# and the safe-regex default, neither of which had anything to do with
# the deleted HTTP transport. They were caught in the same block only
# because they sat next to the endpoint helpers.
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

        # Accepted and IGNORED. Workflows in the wild still pass
        # pii_shield_endpoint, and breaking them would be a worse outcome
        # than carrying a dead input -- but it must never route anything
        # off-box again, so it is not stored and not dialled.
        if self.endpoint:
            print(
                "::warning::pii_shield_endpoint is ignored. PII-Shield now "
                "runs in-process via WASM and makes no network requests.",
                file=sys.stderr,
            )
        self.endpoint = None

        # Also inert, and deliberately so. In pii-shield-wasi 2.1.1 the
        # engine's PII_SAFE_REGEX_LIST variable cannot help and can hurt
        # (measured, both halves): a well-formed [{"pattern","name"}] list
        # is accepted and IGNORED -- output is identical even with a ".*"
        # wildcard -- while anything else terminates the WASM runtime with
        # exit 1 from loadConfig. The old vendored binary honoured the list,
        # which is how a wildcard once switched redaction off entirely; now
        # the knob is a no-op at best and an outage at worst, so it is
        # never forwarded. Warn only when the CALLER passed one -- the
        # default above fills self.safe_regex_list on every run, and
        # warning on our own default would train users to ignore warnings.
        if safe_regex_list:
            print(
                "::warning::pii_shield_safe_regex_list is ignored. The "
                "in-process engine does not accept a caller-supplied "
                "safe-regex list.",
                file=sys.stderr,
            )

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

        # No endpoint condition. Requiring one is what made PII-Shield a
        # no-op in production: the field is documented as an HTTP endpoint,
        # nobody set it, so nothing ever ran.
        if self.mode in {"auto", "remote"}:
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

        # separators MUST keep the space after the colon. Measured against
        # pii-shield-wasi 2.1.1: with compact '":"' the engine redacts
        # NOTHING inside the JSON string values -- '{"a":"alice@x.com"}'
        # comes back untouched while '{"a": "alice@x.com"}' is redacted.
        # With the old compact form, bundle and SARIF sanitization was a
        # silent no-op. The parse below does not care about whitespace, so
        # the spaced form costs nothing.
        original_json = json.dumps(
            work,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ": "),
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
        """Kept as the single entry point so callers are unchanged. The
        name is now a misnomer -- nothing is remote -- but renaming it is
        churn in every call site for no behavioural gain."""
        return self._sanitize_via_wasm(text, input_format, include_findings, purpose)

    def _redact(self, text: str) -> str:
        """The single call into the engine. Isolated so a test can make it
        fail and prove fail-closed still holds after the transport change."""
        wasm_shield_cls, wasm_config_cls = _load_wasm_engine()
        shield = wasm_shield_cls(wasm_config_cls(
            salt=self.salt_fingerprint or None,
            # The engine's own policy knob. Ours is enforced by the caller
            # (sanitize_text re-raises), but passing it through means the
            # engine does not quietly fail open underneath a fail-closed
            # configuration.
            fail_policy="closed" if self.fail_closed else "open",
        ))
        return shield.redact(text)

    def _sanitize_via_wasm(
        self,
        text: str,
        input_format: str,
        include_findings: bool,
        purpose: str | None,
    ) -> PIIShieldResult:
        """In-process redaction via the published pii-shield-wasi package.

        Previously this drove wasmtime directly against a 4 MB
        `lib/pii-shield.wasm` vendored into the repo. Using the package
        means upstream fixes arrive by version bump instead of by copying a
        binary -- which matters, because 2.1.1 carries fixes for redaction
        cascading past a hit and for mangling unbalanced quotes, both of
        which would corrupt a diff we then present as evidence.
        """
        try:
            sanitized = self._redact(text)
        except Exception as exc:
            raise RuntimeError(f"WASM PII-Shield failed: {exc}") from exc

        changed = sanitized != text
        # The engine returns text, not a count. Counting its own marker is
        # the honest approximation available, and it is reported as a count
        # rather than as findings so nobody mistakes it for structured
        # detection the package does not provide.
        redaction_count = sanitized.count("[HIDDEN") if changed else 0

        # Reconstruct zones from the text the engine DID give us. When this
        # was signals=[], entrypoint.py still merged to_sensitive_zones()
        # and the RiskClassifier still scored the result -- so PII silently
        # contributed zero risk while the pipeline looked like it was
        # scoring it. Line-diffing input against output recovers real line
        # numbers with no network call.
        signals = self._signals_from_line_diff(text, sanitized) if changed else []

        return PIIShieldResult(
            sanitized_text=sanitized,
            changed=changed,
            redaction_count=redaction_count,
            # Still empty, and honestly so: redact(str) -> str reports no
            # categories, and inventing per-type counts here would be
            # fabricated detection detail. Zone-level signal now comes from
            # the line diff above instead.
            redactions_by_type={},
            mode="wasm-local",
            provider="pii-shield-wasi",
            input_hash=self._sha256(text),
            output_hash=self._sha256(sanitized),
            signals=signals,
            metadata={
                "input_format": input_format,
                "engine": "wasm",
                "transport": "in-process",
            },
        )

    @staticmethod
    def _signals_from_line_diff(
        original: str,
        sanitized: str,
    ) -> list[dict[str, Any]]:
        """Recover line-level PII zones by diffing input against output.

        The engine changes only lines that contained PII, so a changed
        line IS a finding. Each signal is a location and a count, never
        content: putting the matched value (or even the [HIDDEN:...]
        token) into a zone would turn risk metadata into a PII sink, the
        exact failure this module exists to prevent. The zone/category is
        the constant "pii" because the engine reports no categories --
        redact(str) -> str -- and inventing one would be false precision;
        "pii" is also a key the RiskClassifier's zone_severity map scores.
        """
        in_lines = original.splitlines()
        out_lines = sanitized.splitlines()

        def _signal(line: int | None, count: int) -> dict[str, Any]:
            return {
                "zone": "pii",
                "file": "__pii_shield__",
                "line": line,
                "detector": "pii_shield",
                # Engine does not report categories; single honest constant.
                "category": "pii",
                "count": count,
                "content_preview": "",
            }

        if len(in_lines) == len(out_lines):
            signals = [
                # A changed line with no [HIDDEN marker still counts as 1:
                # the line demonstrably held something the engine removed.
                _signal(idx, max(1, out.count("[HIDDEN")))
                for idx, (src, out) in enumerate(zip(in_lines, out_lines), start=1)
                if src != out
            ]
            if signals:
                return signals

        # Line counts differ (engine reflowed) or the only change was
        # outside splitlines' view (e.g. a trailing newline): zipping would
        # attribute PII to the wrong lines, so degrade to one coarse
        # whole-document zone. Coarse beats silent -- returning [] here is
        # the exact regression the caller's test suite pins.
        return [_signal(None, max(1, sanitized.count("[HIDDEN")))]

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
