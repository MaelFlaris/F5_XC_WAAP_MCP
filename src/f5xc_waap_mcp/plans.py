"""Two-step changes: plan, then apply.

A ``plan_*`` tool computes the exact request body server side, shows a diff,
and stores the body under a random, single-use plan id bound to the caller's
identity, with a short TTL. ``apply_plan`` executes that stored body only after
an explicit human confirmation, and refuses if the object changed since the
plan was made. The model never supplies the body at apply time, so it cannot
swap the payload between plan and apply.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Literal

from .errors import Code, SecureError

MAX_PLANS = 256
MAX_DIFF = 60


@dataclass
class Plan:
    plan_id: str
    identity: str
    operation: Literal["create", "replace"]
    kind: str
    namespace: str
    name: str
    body: dict[str, Any]
    base_version: str | None  # modification timestamp observed when planning
    expires_at: float
    summary: str


class PlanStore:
    def __init__(self, ttl_s: int) -> None:
        self._ttl = ttl_s
        self._plans: dict[str, Plan] = {}
        self._lock = threading.Lock()

    def create(self, **fields: Any) -> Plan:
        plan = Plan(plan_id=f"plan_{secrets.token_urlsafe(18)}", expires_at=time.time() + self._ttl, **fields)
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


def diff(before: Any, after: Any, path: str = "spec", out: list[dict[str, Any]] | None = None) -> list:
    """Compact structural diff (paths and short values), bounded."""
    from .sanitize import redact, text

    out = [] if out is None else out
    if len(out) >= MAX_DIFF:
        return out
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            if key not in after:
                out.append({"op": "remove", "path": f"{path}.{key}"})
            elif key not in before:
                out.append({"op": "add", "path": f"{path}.{key}", "value": text(redact(after[key]), 300)})
            else:
                diff(before[key], after[key], f"{path}.{key}", out)
    elif before != after:
        out.append({"op": "change", "path": path, "before": text(redact(before), 300),
                    "after": text(redact(after), 300)})
    return out
