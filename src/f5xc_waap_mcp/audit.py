"""JSON audit log: one line per event.

Events:
  * ``tool_call``          every tool call (success, denial or error);
  * ``plan_created``       a change was planned (plan_id, target, body hash, risk);
  * ``plan_confirmation``  outcome of the human confirmation for a plan;
  * ``plan_applied``       result of sending a plan to F5 XC.

Each line carries the nominative caller (F5 XC user name / e-mail and UUID,
resolved with whoami), the session, a request id and a hash of the arguments.
Never logged: tokens, argument values, request bodies, response payloads.

File output: created with mode 0600, permissions tightened if the file already
exists, and reopened when it has been rotated (logrotate ``create`` mode). For
Splunk, point a Universal Forwarder at this file (``sourcetype=_json``) or, in
a container, leave the default (stderr) and use the Splunk logging driver.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import threading
from datetime import UTC, datetime
from typing import Any, TextIO

SALT = "f5xc-waap-mcp/audit/v1"


def args_hash(tool: str, args: dict[str, Any]) -> str:
    payload = json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{SALT}:{payload}".encode()).hexdigest()[:16]


class AuditLog:
    def __init__(self, path: str | None = None, stream: TextIO | None = None) -> None:
        self._lock = threading.Lock()
        self._path = path if stream is None else None
        self._inode: int | None = None
        if stream is not None:
            self._stream = stream
        elif path:
            self._stream = self._open(path)
        else:
            self._stream = sys.stderr

    def _open(self, path: str) -> TextIO:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        info = os.fstat(fd)
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.fchmod(fd, 0o600)
        self._inode = info.st_ino
        return os.fdopen(fd, "a", encoding="utf-8")

    def _reopen_if_rotated(self) -> None:
        if self._path is None:
            return
        try:
            current = os.stat(self._path).st_ino
        except FileNotFoundError:
            current = None
        if current != self._inode:
            self._stream.close()
            self._stream = self._open(self._path)

    def emit(self, **record: Any) -> None:
        record = {"ts": datetime.now(UTC).isoformat(timespec="milliseconds"), "schema": "f5xc-waap-mcp/2", **record}
        line = json.dumps(record, sort_keys=True, ensure_ascii=True, default=str)
        with self._lock:
            self._reopen_if_rotated()
            self._stream.write(line + "\n")
            self._stream.flush()
