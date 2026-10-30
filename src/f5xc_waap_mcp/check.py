"""``f5xc-waap-mcp check``: validate the tenant prerequisites before going live.

Run it first on a real tenant, with the personal token of a user holding the
role intended for the server (``F5XC_API_TOKEN``, read from the environment):

  1. whoami: does XC return the owner of an API token, and which fields
     (name, email, user_uuid, type) are filled? This is the identity every
     call depends on;
  2. for each allow-listed namespace: can this role list HTTP load balancers
     and read the active service policies?

Nothing is written to XC. The token is never printed.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from . import catalog
from .config import Settings
from .errors import Code, SecureError
from .identity import IdentityResolver
from .xc_client import XCClient

WHOAMI_FIELDS = ("name", "email", "user_uuid", "type", "state", "disabled")


HINTS = {
    302: "XC redirected (observed for an unknown tenant): check F5XC_TENANT, the short tenant id.",
    401: "Token rejected by XC: expired, revoked, or not an API token.",
    403: "Authenticated but not authorized: the user's role cannot perform this read.",
}


def _error(exc: SecureError) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": False, "error_code": str(exc.code), "http_status": exc.status}
    if exc.status in HINTS:
        out["hint"] = HINTS[exc.status]
    return out


async def run_check(settings: Settings, client: XCClient | None = None) -> dict[str, Any]:
    client = client or XCClient(settings)
    token = settings.api_token
    if token is None:  # Settings already refuses stdio without a token
        raise SecureError(Code.UNAUTHENTICATED)
    report: dict[str, Any] = {"tenant": settings.tenant, "identity": {}, "namespaces": {}}
    method, path = catalog.data_path("identity.whoami", namespace="system")
    try:
        payload = await client.request(method, path, token)
        payload = payload if isinstance(payload, dict) else {}
        report["identity"]["whoami_fields_present"] = [
            f for f in WHOAMI_FIELDS if payload.get(f) not in (None, "", [])
        ]
        try:
            principal = IdentityResolver(settings, client)._principal(payload)
            report["identity"].update(ok=True, user=principal.user, user_type=principal.user_type,
                                      user_uuid_present=bool(principal.user_uuid))
        except SecureError as exc:
            report["identity"].update(_error(exc), hint=exc.hint or None)
    except SecureError as exc:
        report["identity"].update(_error(exc))
    lb = catalog.kind("http_loadbalancer")
    for namespace in settings.allowed_namespaces:
        result: dict[str, Any] = {}
        try:
            listing = await client.request("GET", catalog.kind_path(lb, "list", namespace=namespace), token)
            result["list_http_loadbalancers"] = {"ok": True, "count": len(listing.get("items", []))}
        except SecureError as exc:
            result["list_http_loadbalancers"] = _error(exc)
        try:
            m, p = catalog.data_path("namespace.active_service_policies", namespace=namespace)
            await client.request(m, p, token)
            result["active_service_policies"] = {"ok": True}
        except SecureError as exc:
            result["active_service_policies"] = _error(exc)
        report["namespaces"][namespace] = result
    await client.aclose()
    report["ok"] = bool(report["identity"].get("ok"))
    return report


def main(settings: Settings) -> int:
    report = asyncio.run(run_check(settings))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1
