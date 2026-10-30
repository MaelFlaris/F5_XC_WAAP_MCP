"""Argument types shared by the tools (no ``from __future__ import annotations``:
FastMCP evaluates these annotations to build the tool JSON schemas)."""

import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from ..config import Settings
from ..errors import Code, SecureError

XC_NAME = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"

Namespace = Annotated[str, StringConstraints(min_length=1, max_length=63, pattern=XC_NAME),
                      Field(description="F5 XC namespace (must be allow-listed on the server).")]
ObjectName = Annotated[str, StringConstraints(min_length=1, max_length=63, pattern=XC_NAME),
                       Field(description="Object name (lowercase, digits, dashes).")]
TimeSpec = Annotated[str, StringConstraints(min_length=2, max_length=40),
                     Field(description="RFC 3339 timestamp, or a relative duration back from now such as "
                                       "'15m', '1h', '24h', '7d'.")]

_RELATIVE = re.compile(r"^(\d{1,4})([mhd])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def parse_time(value: str, now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    match = _RELATIVE.match(value.strip())
    if match:
        return now - timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise SecureError(Code.INVALID_ARGUMENT, "Time must be RFC 3339 or like '1h' / '7d'.") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def time_window(settings: Settings, start: str, end: str | None) -> tuple[str, str]:
    now = datetime.now(UTC)
    start_dt = parse_time(start, now)
    end_dt = parse_time(end, now) if end else now
    if start_dt >= end_dt:
        raise SecureError(Code.INVALID_ARGUMENT, "start must be before end.")
    if end_dt - start_dt > timedelta(hours=settings.max_query_window_h):
        raise SecureError(Code.INVALID_ARGUMENT, f"Window larger than {settings.max_query_window_h}h.")
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    return start_dt.astimezone(UTC).strftime(fmt), end_dt.astimezone(UTC).strftime(fmt)


# --- query matchers -----------------------------------------------------------
# XC log queries use the syntax {field="value", field2=~"regex"}. Values cannot
# contain quotes, braces or backslashes, so a matcher can never break out of
# its string. Field lists:
#   * access / audit logs: exactly the fields listed in the API reference;
#   * security events: the 4 documented fields (vh_name, src_site, city,
#     country) + app_type (doc example) + fields named after the documented
#     aggregation keys (src_ip, sec_event_type...). The latter are not listed
#     as matchers in the reference: see docs/UNCERTAINTIES.md.
EventField = Literal[
    "vh_name", "src_site", "city", "country", "app_type", "src_ip", "sec_event_type", "sec_event_name",
    "action", "domain", "method", "req_path", "rsp_code", "waf_mode", "asn", "user",
]
AccessLogField = Literal[
    "app_type", "vh_name", "src_site", "src", "src_instance", "dst_site", "dst", "dst_instance", "method",
    "req_path", "rsp_code", "browser_type", "city", "country", "device_type",
]
AuditLogField = Literal[
    "user", "src_site", "src", "src_instance", "dst_site", "dst", "dst_instance", "method", "req_path", "rsp_code",
]
_SAFE_VALUE = re.compile(r'^[^"{}\\\n\r]{1,200}$')


class Matcher(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    op: Literal["=", "!=", "=~", "!~"] = "="
    value: Annotated[str, StringConstraints(min_length=1, max_length=200)]


class EventMatcher(Matcher):
    field: EventField


class AccessLogMatcher(Matcher):
    field: AccessLogField


class AuditLogMatcher(Matcher):
    field: AuditLogField


def build_query(matchers: list[Matcher] | None) -> str:
    if not matchers:
        return "{}"
    if len(matchers) > 10:
        raise SecureError(Code.INVALID_ARGUMENT, "At most 10 filters.")
    parts = []
    for m in matchers:
        if not _SAFE_VALUE.match(m.value):
            raise SecureError(Code.INVALID_ARGUMENT, 'Filter values cannot contain " { } \\ or newlines.')
        parts.append(f'{m.field}{m.op}"{m.value}"')
    return "{" + ", ".join(parts) + "}"
