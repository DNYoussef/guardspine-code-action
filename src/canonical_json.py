# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 GuardSpine, Inc.
# Licensed under the Business Source License 1.1. See LICENSE for terms.
# Change License: Apache-2.0. Change Date: see LICENSE.
"""
Canonical JSON helpers for deterministic hashing/signing.

This module normalizes values to a stable JSON representation:
  - dict keys are sorted lexicographically
  - sets/frozensets become sorted lists
  - non-finite floats are rejected

IMPORTANT: No Unicode normalization (NFC/NFD) is applied.
Strings are passed through as-is to match kernel canonical behavior
(guardspine-kernel/src/canonical.ts).
"""


import json
import math
from dataclasses import asdict, is_dataclass
from datetime import datetime, date
from typing import Any


def canonicalize_for_json(value: Any) -> Any:
    """Recursively normalize a Python value for canonical JSON encoding."""
    if value is None or isinstance(value, (bool, int)):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite floats are not allowed in canonical JSON")
        return value

    if isinstance(value, str):
        return value

    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="strict")

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if is_dataclass(value):
        return canonicalize_for_json(asdict(value))

    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key in sorted(value.keys(), key=lambda k: str(k)):
            normalized_key = str(key) if not isinstance(key, str) else key
            if normalized_key in normalized:
                raise ValueError(f"Canonical key collision detected for key {normalized_key!r}")
            normalized[normalized_key] = canonicalize_for_json(value[key])
        return normalized

    if isinstance(value, (list, tuple)):
        return [canonicalize_for_json(item) for item in value]

    if isinstance(value, (set, frozenset)):
        normalized_items = [canonicalize_for_json(item) for item in value]
        normalized_items.sort(
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        )
        return normalized_items

    return str(value)


def canonical_json_dumps(value: Any) -> str:
    """Serialize a value as canonical JSON.

    The FINAL serialization is delegated to guardspine-kernel's RFC 8785
    canonicalizer -- the exact same implementation the GuardSpine backend uses
    to re-verify a bundle's hash chain and signature on import. Python's
    json.dumps diverges from RFC 8785 on numbers (e.g. a float 1.0 serializes
    as "1.0" instead of "1"), so a bundle carrying an AI-emitted float score
    would hash/sign differently on the action side than the backend recomputes,
    and the backend would reject the import (422). Delegating here keeps the
    two sides byte-identical for every value type, not just the no-float case.
    canonicalize_for_json still runs first to reduce non-JSON Python types
    (dataclasses, datetime, bytes, sets) to JSON-native values the kernel
    canonicalizer accepts.
    """
    normalized = canonicalize_for_json(value)
    from guardspine_kernel.canonical import canonical_json as _kernel_canonical_json

    return _kernel_canonical_json(normalized)


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize canonical JSON as UTF-8 bytes."""
    return canonical_json_dumps(value).encode("utf-8")
