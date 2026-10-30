"""Entry point: ``f5xc-waap-mcp`` or ``python -m f5xc_waap_mcp``."""

from __future__ import annotations

import json
import sys

from pydantic import ValidationError

from .config import get_settings
from .server import build_server, run


def main() -> int:
    try:
        settings = get_settings()
    except ValidationError as exc:
        # Field names and messages only, never the values (they may be tokens).
        for err in exc.errors(include_input=False, include_url=False):
            location = ".".join(str(p) for p in err.get("loc", ())) or "settings"
            sys.stderr.write(f"f5xc-waap-mcp: configuration error: {location}: {err.get('msg')}\n")
        return 2
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
