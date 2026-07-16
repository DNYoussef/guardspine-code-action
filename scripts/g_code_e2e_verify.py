#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 GuardSpine, Inc.
# Licensed under the Business Source License 1.1. See LICENSE for terms.
# Change License: Apache-2.0. Change Date: see LICENSE.
"""
G-CODE-E2E read-back + verify.

Reads back the EXACT evidence bundle the CodeGuard action just wrote to the
GuardSpine backend (GET /bundles/import/{bundle_id}, project-API-key auth --
the same credential the action used for POST /bundles/import) and asserts it
is the one verified, ID-traceable dashboard record the gate exists to prove.

Exits 1 (RED) on ANY assertion failure -- a failed read-back or
verified != True must fail the job, never silently pass as green.

Usage:
    GUARDSPINE_API_KEY=<key> python scripts/g_code_e2e_verify.py <api_url> <bundle_id>

<api_url> is the base API URL INCLUDING /api/v1, e.g.
https://api.guardspine.ai/api/v1 -- the script GETs
<api_url>/bundles/import/<bundle_id>.

Stdlib only (urllib, json) -- no third-party deps, matching entrypoint.py's
own backend-call style (see entrypoint.py:_post_to_backend).
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional


class _StripAuthOnCrossOriginRedirect(urllib.request.HTTPRedirectHandler):
    """Drop the Authorization header if a redirect crosses origin, so a
    backend/CDN redirect cannot forward the project API key to another host.
    Same-origin redirects keep the credential; cross-origin ones do not."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            def _origin(u):
                s = urllib.parse.urlsplit(u)
                # Normalize the default port so https://h and https://h:443 are
                # the SAME origin (an explicit-default-port redirect must not
                # spuriously strip auth).
                port = s.port or {"https": 443, "http": 80}.get(s.scheme)
                return (s.scheme, s.hostname, port)

            if _origin(req.full_url) != _origin(newurl):
                for store in (getattr(new, "headers", {}), getattr(new, "unredirected_hdrs", {})):
                    for k in [h for h in store if h.lower() == "authorization"]:
                        store.pop(k, None)
        return new


_ORIGIN_SAFE_OPENER = urllib.request.build_opener(_StripAuthOnCrossOriginRedirect)


class VerifyFailure(Exception):
    """One assertion failed. The message is the exact reason -- printed
    verbatim as ::error:: so the gate's red is never ambiguous."""


def fetch_import_result(api_url: str, api_key: str, bundle_id: str) -> dict[str, Any]:
    """GET /bundles/import/{bundle_id}.

    Raises VerifyFailure on any non-200 response, unreachable host, or
    unparseable body -- there is no "partial success" return value here;
    every failure mode becomes the same fatal signal the caller propagates.
    """
    url = api_url.rstrip("/") + f"/bundles/import/{bundle_id}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        resp = _ORIGIN_SAFE_OPENER.open(req, timeout=15)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise VerifyFailure(
            f"read-back GET {url} failed: HTTP {exc.code}: {detail}"
        ) from exc
    except urllib.error.URLError as exc:
        raise VerifyFailure(f"read-back GET {url} unreachable: {exc.reason}") from exc

    status = getattr(resp, "status", None) or resp.getcode()
    raw = resp.read()
    if status != 200:
        raise VerifyFailure(
            f"read-back GET {url} returned HTTP {status} (expected 200)"
        )
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise VerifyFailure(f"read-back GET {url} returned non-JSON body: {exc}") from exc
    if not isinstance(parsed, dict):
        raise VerifyFailure(f"read-back GET {url} returned a non-object JSON body")
    return parsed


def assert_verified_bundle(result: dict[str, Any], expected_bundle_id: str) -> dict[str, Any]:
    """Assert the ImportBundleResult is the one exact verified bundle the
    action just wrote.

    Checks, in order (first failure wins -- no partial credit):
      1. bundle_id matches what the action emitted (ID-traceable: the EXACT
         bundle the action wrote is the one read back).
      2. verified is True (STRICT identity check, not truthy).
      3. root_hash is present and non-empty.
      4. item_count is an int > 0.

    Returns the asserted field subset on success.
    """
    actual_bundle_id = result.get("bundle_id")
    if actual_bundle_id != expected_bundle_id:
        raise VerifyFailure(
            f"bundle_id mismatch: action emitted {expected_bundle_id!r}, "
            f"read-back returned {actual_bundle_id!r}"
        )

    if result.get("verified") is not True:
        raise VerifyFailure(
            f"bundle {expected_bundle_id} is not verified "
            f"(verified={result.get('verified')!r})"
        )

    root_hash = result.get("root_hash")
    _SHA256_HEXLEN = 64
    _hex = root_hash[len("sha256:"):] if isinstance(root_hash, str) else ""
    if (
        not isinstance(root_hash, str)
        or not root_hash
        or not root_hash.startswith("sha256:")
        or len(_hex) != _SHA256_HEXLEN
        # Require actual lowercase hex, not just any 64 chars (e.g. "sha256:"
        # followed by 64 'z' must fail).
        or any(c not in "0123456789abcdef" for c in _hex)
    ):
        raise VerifyFailure(
            f"bundle {expected_bundle_id} has an invalid root_hash "
            f"(expected a 'sha256:<64 lowercase hex chars>' string, got {root_hash!r})"
        )

    item_count = result.get("item_count")
    if not isinstance(item_count, int) or isinstance(item_count, bool) or item_count <= 0:
        raise VerifyFailure(
            f"bundle {expected_bundle_id} has item_count={item_count!r} (expected int > 0)"
        )

    return {
        "bundle_id": actual_bundle_id,
        "raw_sha256": result.get("raw_sha256"),
        "imported_at": result.get("imported_at"),
        "verified": result.get("verified"),
        "version": result.get("version"),
        "item_count": item_count,
        "root_hash": root_hash,
    }


def verify(api_url: str, api_key: str, bundle_id: str) -> dict[str, Any]:
    """Full read-back + assert. Raises VerifyFailure on any failure."""
    result = fetch_import_result(api_url, api_key, bundle_id)
    return assert_verified_bundle(result, bundle_id)


def main(argv: Optional[list[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print(
            "usage: g_code_e2e_verify.py <api_url> <bundle_id>",
            file=sys.stderr,
        )
        return 1
    api_url, bundle_id = argv

    if not bundle_id:
        print("::error::g_code_e2e_verify: empty bundle_id (the action did not emit one)")
        return 1

    api_key = os.environ.get("GUARDSPINE_API_KEY", "")
    if not api_key:
        print("::error::g_code_e2e_verify: GUARDSPINE_API_KEY is not set")
        return 1

    try:
        fields = verify(api_url, api_key, bundle_id)
    except VerifyFailure as exc:
        print(f"::error::g_code_e2e_verify: {exc}")
        return 1

    print("g_code_e2e_verify: PASS -- one exact verified dashboard bundle read back")
    for key in (
        "bundle_id",
        "verified",
        "version",
        "item_count",
        "root_hash",
        "raw_sha256",
        "imported_at",
    ):
        print(f"  {key}: {fields.get(key)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
