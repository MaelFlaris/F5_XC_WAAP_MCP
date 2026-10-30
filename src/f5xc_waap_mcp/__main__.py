"""Entry point: ``f5xc-waap-mcp`` (serve) or ``f5xc-waap-mcp check`` (tenant prerequisites)."""

from __future__ import annotations

import json
import sys

from pydantic import ValidationError

from .config import Transport, get_settings, settings_from_fields
from .server import build_server, run


def main() -> int:
    checking = sys.argv[1:2] == ["check"]
    try:
        # ``check`` uses the operator's own F5XC_API_TOKEN and serves nothing,
        # whatever the transport configured for the server.
        settings = (
            settings_from_fields(transport=Transport.STDIO, bind_host="127.0.0.1")
            if checking else get_settings()
        )
    except ValidationError as exc:
        # Field names and messages only, never the values (they may be tokens).
        for err in exc.errors(include_input=False, include_url=False):
            location = ".".join(str(p) for p in err.get("loc", ())) or "settings"
            sys.stderr.write(f"f5xc-waap-mcp: configuration error: {location}: {err.get('msg')}\n")
        return 2
    if checking:
        from .check import main as check_main

        return check_main(settings)
    mcp, rt = build_server(settings)
    sys.stderr.write(json.dumps({
        "event": "startup", "tenant": settings.tenant, "mode": settings.mode, "transport": settings.transport,
        "writes_enabled": settings.writes_enabled, "namespaces": list(settings.allowed_namespaces),
        "tools": sorted(rt.registered),
    }) + "\n")
    run(mcp, settings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
