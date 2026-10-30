"""Two-step changes: plan, then apply.

A ``plan_*`` tool computes the exact request body server side and stores it
under a random, single-use plan id bound to the caller, with a short TTL.
``apply_plan`` executes that stored body only after a human confirmation whose
message contains the complete diff and the body hash, and refuses if the
object changed since the plan was made.

The diff is exhaustive or the plan is refused: every changed leaf is listed
(lists of named items are matched by name, re-ordering is reported), values
are shown JSON-escaped and never truncated. Changes touching secret fields are
refused outright, since they could not be shown to the reviewer.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from .errors import Code, SecureError

MAX_PLANS = 256
MAX_DIFF_OPS = 80
MAX_VALUE_CHARS = 300
MAX_RENDER_CHARS = 8000

_SECRET_PATH = re.compile(
    r"(?i)(private_key|password|passwd|secret|token|api_?key|client_secret|hmac|credential|pkcs12)"
)


@dataclass
class Plan:
    plan_id: str
    identity: str
    operation: Literal["create", "replace"]
    kind: str
    namespace: str
    name: str
    method: str
    path: str
    body: dict[str, Any]
    body_sha256: str
    base_version: str | None  # hash of the spec observed when planning (replace only)
    expires_at: float
    summary: str
    diff: list[dict[str, Any]]
    risks: list[str] = field(default_factory=list)
    before: dict[str, Any] | None = None  # spec observed when planning (replace), kept for rollback

    @property
    def high_risk(self) -> bool:
        return bool(self.risks)


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class PlanStore:
    def __init__(self, ttl_s: int) -> None:
        self._ttl = ttl_s
        self._plans: dict[str, Plan] = {}
        self._lock = threading.Lock()

    def create(self, **fields: Any) -> Plan:
        body = fields["body"]
        plan = Plan(
            plan_id=f"plan_{secrets.token_urlsafe(18)}",
            expires_at=time.time() + self._ttl,
            body_sha256=canonical_hash({"method": fields["method"], "path": fields["path"], "body": body}),
            **fields,
        )
        with self._lock:
            self._evict()
            self._plans[plan.plan_id] = plan
        return plan

    def take(self, plan_id: str, identity: str) -> Plan:
        """Remove and return the plan (single use)."""
        with self._lock:
            self._evict()
            plan = self._plans.get(plan_id)
            if plan is None:
                raise SecureError(Code.PLAN_UNKNOWN)
            if not secrets.compare_digest(plan.identity, identity):
                raise SecureError(Code.PLAN_USER_MISMATCH)
            del self._plans[plan_id]
            return plan

    def _evict(self) -> None:
        now = time.time()
        for plan_id in [p for p, plan in self._plans.items() if plan.expires_at < now]:
            del self._plans[plan_id]
        while len(self._plans) >= MAX_PLANS:
            self._plans.pop(next(iter(self._plans)))


# --- diff ---------------------------------------------------------------------
def _show(value: Any) -> str:
    """JSON-escaped (control, bidi and non-ASCII characters visible), never truncated."""
    shown = json.dumps(value, sort_keys=True, ensure_ascii=True)
    if len(shown) > MAX_VALUE_CHARS:
        raise SecureError(Code.DIFF_TOO_LARGE, f"A value is longer than {MAX_VALUE_CHARS} characters.")
    return shown


_PLAIN_KEY = re.compile(r"^[A-Za-z0-9_\-]{1,80}$")


def _seg(key: Any) -> str:
    """Path segment safe to print: odd keys are JSON-escaped so they cannot fake diff lines."""
    key = str(key)
    return key if _PLAIN_KEY.fullmatch(key) else json.dumps(key, ensure_ascii=True)[:120]


def _item_key(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    meta = item.get("metadata")
    name = meta.get("name") if isinstance(meta, dict) else item.get("name")
    return name if isinstance(name, str) else None


def _keyed(items: list[Any]) -> dict[str, Any] | None:
    keys = [_item_key(i) for i in items]
    if not items or None in keys or len(set(keys)) != len(keys):
        return None
    return dict(zip(keys, items, strict=True))


class _Differ:
    def __init__(self) -> None:
        self.ops: list[dict[str, Any]] = []

    def _add(self, op: dict[str, Any]) -> None:
        if _SECRET_PATH.search(op["path"]):
            raise SecureError(Code.SECRET_FIELD, f"Field {op['path'][:120]}.")
        self.ops.append(op)
        if len(self.ops) > MAX_DIFF_OPS:
            raise SecureError(Code.DIFF_TOO_LARGE, f"More than {MAX_DIFF_OPS} changed fields.")

    def leaves(self, op: str, value: Any, path: str) -> None:
        """Emit one op per leaf so that nothing is hidden in a big value."""
        if isinstance(value, dict) and value:
            for key in sorted(value):
                self.leaves(op, value[key], f"{path}.{_seg(key)}")
        elif isinstance(value, list) and value:
            keyed = _keyed(value)
            for index, item in enumerate(value):
                label = f"[{_seg(_item_key(item))}]" if keyed else f"[{index}]"
                self.leaves(op, item, f"{path}{label}")
        else:
            entry = {"op": op, "path": path}
            entry["after" if op == "add" else "before"] = _show(value)
            self._add(entry)

    def removed(self, value: Any, path: str) -> None:
        """A key or list item that disappears. Its leaves are listed, then one explicit
        line says the container itself is gone: otherwise "object removed" and
        "object emptied" would render identically (an empty object can select an
        XC option)."""
        self.leaves("remove", value, path)
        if isinstance(value, dict | list) and value:
            self._add({"op": "remove", "path": path, "whole": "object" if isinstance(value, dict) else "list"})

    def diff(self, before: Any, after: Any, path: str) -> None:
        if isinstance(before, dict) and isinstance(after, dict):
            for key in sorted(set(before) | set(after)):
                sub = f"{path}.{_seg(key)}"
                if key not in after:
                    self.removed(before[key], sub)
                elif key not in before:
                    self.leaves("add", after[key], sub)
                else:
                    self.diff(before[key], after[key], sub)
        elif isinstance(before, list) and isinstance(after, list):
            self._diff_list(before, after, path)
        elif type(before) is not type(after) or json.dumps(before) != json.dumps(after):
            # Compare what is sent, not Python equality: true != 1, 1 != 1.0, 0.0 != -0.0.
            self._add({"op": "change", "path": path, "before": _show(before), "after": _show(after)})

    def _diff_list(self, before: list[Any], after: list[Any], path: str) -> None:
        kb, ka = _keyed(before), _keyed(after)
        if kb is not None and ka is not None:
            for key in kb:
                if key not in ka:
                    self.removed(kb[key], f"{path}[{_seg(key)}]")
            for key in ka:
                if key in kb:
                    self.diff(kb[key], ka[key], f"{path}[{_seg(key)}]")
                else:
                    self.leaves("add", ka[key], f"{path}[{_seg(key)}]")
            common_before = [k for k in kb if k in ka]
            common_after = [k for k in ka if k in kb]
            if common_before != common_after:  # rule order matters (first match wins)
                self._add({"op": "reorder", "path": path, "before": _show(common_before),
                           "after": _show(common_after)})
            return
        for index in range(max(len(before), len(after))):
            sub = f"{path}[{index}]"
            if index >= len(after):
                self.removed(before[index], sub)
            elif index >= len(before):
                self.leaves("add", after[index], sub)
            else:
                self.diff(before[index], after[index], sub)


def diff(before: Any, after: Any, path: str = "spec") -> list[dict[str, Any]]:
    """Exhaustive structural diff; raises DIFF_TOO_LARGE / SECRET_FIELD instead of hiding anything."""
    differ = _Differ()
    differ.diff(before, after, path)
    if len(render(differ.ops)) > MAX_RENDER_CHARS:
        raise SecureError(Code.DIFF_TOO_LARGE, f"Diff longer than {MAX_RENDER_CHARS} characters.")
    return differ.ops


def render(ops: list[dict[str, Any]]) -> str:
    lines = []
    for op in ops:
        if op["op"] == "add":
            lines.append(f"+ {op['path']} = {op['after']}")
        elif op["op"] == "remove" and "whole" in op:
            lines.append(f"- {op['path']} (whole {op['whole']} removed)")
        elif op["op"] == "remove":
            lines.append(f"- {op['path']} (was {op['before']})")
        elif op["op"] == "reorder":
            lines.append(f"~ {op['path']} order {op['before']} -> {op['after']}")
        else:
            lines.append(f"~ {op['path']}: {op['before']} -> {op['after']}")
    return "\n".join(lines)
