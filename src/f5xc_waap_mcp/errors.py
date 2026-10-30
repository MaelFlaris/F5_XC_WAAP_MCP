"""Sanitised errors.

``str(SecureError)`` is what FastMCP sends back to the client (as a tool error
with ``isError=true``), so it only ever contains a stable code and a fixed
message. Technical detail stays in ``detail`` for the audit log, after
scrubbing.
"""

from __future__ import annotations

import re
from enum import StrEnum

_SCRUB = (
    re.compile(r"(?i)(apitoken|authorization|bearer|token|secret|password)[\"']?\s*[:=]\s*\S+"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}"),
    re.compile(r"https?://\S+"),
)


def scrub(text: str, limit: int = 200) -> str:
    for pattern in _SCRUB:
        text = pattern.sub("[redacted]", text)
    return text[:limit]


class Code(StrEnum):
    UNAUTHENTICATED = "unauthenticated"
    AUTH_RATE_LIMITED = "auth_rate_limited"
    NAMESPACE_FORBIDDEN = "namespace_forbidden"
    NAMESPACE_PROTECTED = "namespace_protected"
    KIND_NOT_WRITABLE = "kind_not_writable"
    SENSITIVE_KIND = "sensitive_kind"
    INVALID_ARGUMENT = "invalid_argument"
    RATE_LIMITED = "rate_limited"
    SESSION_CAP_REACHED = "session_cap_reached"
    LOOP_DETECTED = "loop_detected"
    UPSTREAM_FORBIDDEN = "upstream_forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    UPSTREAM_RATE_LIMITED = "upstream_rate_limited"
    UPSTREAM_ERROR = "upstream_error"
    UPSTREAM_TIMEOUT = "upstream_timeout"
    UPSTREAM_UNREACHABLE = "upstream_unreachable"
    UPSTREAM_REDIRECT = "upstream_redirect_refused"
    RESPONSE_TOO_LARGE = "response_too_large"
    RESPONSE_INVALID = "response_invalid"
    DIFF_TOO_LARGE = "diff_too_large"
    SECRET_FIELD = "secret_field_refused"  # noqa: S105 - error code, not a secret
    PLAN_UNKNOWN = "plan_unknown_or_expired"
    PLAN_USER_MISMATCH = "plan_user_mismatch"
    PLAN_STALE = "plan_stale"
    CONFIRMATION_REQUIRED = "confirmation_required"
    INTERNAL = "internal_error"


MESSAGES: dict[Code, str] = {
    Code.UNAUTHENTICATED: "No usable F5 XC credential for this request.",
    Code.AUTH_RATE_LIMITED: "Too many token validations, retry later.",
    Code.NAMESPACE_FORBIDDEN: "Namespace is not in the server allow-list.",
    Code.NAMESPACE_PROTECTED: "Namespace is protected and cannot be modified through this server.",
    Code.KIND_NOT_WRITABLE: "This object kind is read-only in this server.",
    Code.SENSITIVE_KIND: "This object kind may hold secrets: only the summary view is available.",
    Code.INVALID_ARGUMENT: "Invalid argument.",
    Code.RATE_LIMITED: "Rate limit reached, retry later.",
    Code.SESSION_CAP_REACHED: "Call budget of this session is exhausted.",
    Code.LOOP_DETECTED: "Same call repeated too many times in a row; change the arguments or stop.",
    Code.UPSTREAM_FORBIDDEN: "F5 XC refused the call (token invalid or RBAC role insufficient).",
    Code.NOT_FOUND: "Object not found.",
    Code.CONFLICT: "F5 XC reported a conflict (object exists or was modified).",
    Code.UPSTREAM_RATE_LIMITED: "F5 XC is rate limiting the calls.",
    Code.UPSTREAM_ERROR: "F5 XC returned an error.",
    Code.UPSTREAM_TIMEOUT: "F5 XC did not answer in time.",
    Code.UPSTREAM_UNREACHABLE: "F5 XC is unreachable.",
    Code.UPSTREAM_REDIRECT: "Redirect refused by security policy.",
    Code.RESPONSE_TOO_LARGE: "F5 XC response exceeds the configured size limit.",
    Code.RESPONSE_INVALID: "F5 XC response could not be parsed.",
    Code.DIFF_TOO_LARGE: "The change is too large to be reviewed in full; split it into smaller changes.",
    Code.SECRET_FIELD: "Changes touching secret fields are refused by this server.",
    Code.PLAN_UNKNOWN: "Unknown, expired or already used plan id.",
    Code.PLAN_USER_MISMATCH: "This plan was created by another identity.",
    Code.PLAN_STALE: "The object changed since the plan was created; create a new plan.",
    Code.CONFIRMATION_REQUIRED: "Change not applied: explicit human confirmation is required.",
    Code.INTERNAL: "Internal error.",
}


class SecureError(Exception):
    """Error whose string form is safe to return to the client."""

    def __init__(self, code: Code, hint: str = "", *, detail: str = "", status: int | None = None) -> None:
        self.code = code
        # ``hint`` is server-authored text (never upstream content) shown to the client.
        self.hint = hint[:300]
        self.detail = scrub(detail)
        self.status = status
        super().__init__(str(self))

    def __str__(self) -> str:
        base = f"{self.code}: {MESSAGES[self.code]}"
        return f"{base} {self.hint}" if self.hint else base
