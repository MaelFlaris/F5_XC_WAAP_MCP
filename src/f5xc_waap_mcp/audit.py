"""JSON audit log: one line per tool call (success, denial or error).

Logged: timestamp, request id, session, pseudonymised identity, tool, tool
class, sha256 of the arguments, namespace, target, status, error code, latency.
Never logged: tokens, argument values, response payloads.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from datetime import UTC, datetime
from typing import Any, TextIO

SALT = "f5xc-waap-mcp/audit/v1"


def args_hash(tool: str, args: dict[str, Any]) -> str:
    payload = json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{SALT}:{payload}".encode()).hexdigest()[:16]


def pseudonym(value: str) -> str:
    return hashlib.sha256(f"{SALT}:id:{value}".encode()).hexdigest()[:16]


class AuditLog:
    def __init__(self, path: str | None = None, stream: TextIO | None = None) -> None:
        self._lock = threading.Lock()
        if stream is not None:
            self._stream = stream
        elif path:
            self._stream = open(path, "a", encoding="utf-8")  # noqa: SIM115 - kept open for the process
        else:
            self._stream = sys.stderr

    def emit(self, **record: Any) -> None:
        record = {"ts": datetime.now(UTC).isoformat(timespec="milliseconds"), "schema": "f5xc-waap-mcp/1", **record}
        line = json.dumps(record, sort_keys=True, ensure_ascii=True, default=str)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()
