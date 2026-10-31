"""Shared runtime: identity resolution, tool registration by class, and the
single control chain every tool goes through:

    identity (validated by XC) -> guardrails -> tool body -> audit (success or failure)

Tools are registered with FastMCP only when their class is allowed by the
configuration: in read mode, write tools do not exist in ``tools/list``.
"""

from __future__ import annotations

import functools
import inspect
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import SecretStr

from .audit import AuditLog, args_hash
from .config import API_TOKEN_RE, Settings, Transport
from .errors import Code, SecureError
from .guardrails import Guardrails
from .identity import IdentityResolver, Principal
from .plans import PlanStore
from .topics import TOOL_TOPICS, WRITES
from .xc_client import XCClient

TOKEN_HEADER = "x-f5xc-api-token"  # noqa: S105 - header name, not a secret


class ToolClass(StrEnum):
    READ = "read"
    WRITE = "write"


@dataclass(frozen=True)
class Identity:
    principal: Principal
    token: SecretStr
    session: str

    @property
    def key(self) -> str:
        return self.principal.key


_current: ContextVar[Identity | None] = ContextVar("f5xc_identity", default=None)
# Per-call audit context: request id, caller, and fields added by the tool body.
_audit_ctx: ContextVar[dict[str, Any] | None] = ContextVar("f5xc_audit", default=None)
_SESSION_ATTR = "_f5xc_session_id"


def session_id(session: Any) -> str:
    """Random id attached to the MCP session object (never reused, unlike id())."""
    value = getattr(session, _SESSION_ATTR, None)
    if value is None:
        value = f"ses_{uuid.uuid4().hex}"
        setattr(session, _SESSION_ATTR, value)
    return value


class Runtime:
    def __init__(self, settings: Settings, client: XCClient | None = None, audit: AuditLog | None = None) -> None:
        self.settings = settings
        self.client = client or XCClient(settings)
        self.guardrails = Guardrails(settings)
        self.audit = audit or AuditLog(settings.audit_path)
        self.plans = PlanStore(settings.plan_ttl_s)
        self.identities = IdentityResolver(settings, self.client)
        self.registered: dict[str, ToolClass] = {}

    # -- identity ------------------------------------------------------------
    def _token(self, ctx: Context) -> SecretStr:
        if self.settings.transport is Transport.STDIO:
            if self.settings.api_token is None:
                raise SecureError(Code.UNAUTHENTICATED)
            return self.settings.api_token
        request = ctx.request_context.request
        headers = getattr(request, "headers", None)
        raw = headers.get(TOKEN_HEADER) if headers is not None else None
        if not raw or not API_TOKEN_RE.fullmatch(raw.strip()):
            raise SecureError(Code.UNAUTHENTICATED, "Send your personal F5 XC API token in X-F5XC-API-Token.")
        return SecretStr(raw.strip())

    async def resolve_identity(self, ctx: Context) -> Identity:
        token = self._token(ctx)
        principal = await self.identities.resolve(token)  # validated by XC before any quota
        return Identity(principal, token, session_id(ctx.request_context.session))

    @staticmethod
    def identity() -> Identity:
        ident = _current.get()
        if ident is None:
            raise SecureError(Code.UNAUTHENTICATED)
        return ident

    # -- audit -------------------------------------------------------------
    @staticmethod
    def annotate(**fields: Any) -> None:
        """Add fields (namespace, target, plan_id...) to the audit line of the current call."""
        context = _audit_ctx.get()
        if context is not None:
            context["extra"].update(fields)

    def audit_event(self, event: str, **fields: Any) -> None:
        """Dedicated audit event tied to the current call (same request id and user)."""
        context = _audit_ctx.get() or {}
        ident = _current.get()
        self.audit.emit(
            event=event, request_id=context.get("request_id"), session=ident.session if ident else None,
            user=ident.principal.user if ident else None, user_uuid=ident.principal.user_uuid if ident else None,
            **fields,
        )

    # -- XC helpers ----------------------------------------------------------
    async def xc(self, method: str, path: str, **kwargs: Any) -> Any:
        return await self.client.request(method, path, self.identity().token, **kwargs)

    def require_namespace(self, namespace: str, *, write: bool = False) -> None:
        if not self.settings.namespace_allowed(namespace):
            raise SecureError(Code.NAMESPACE_FORBIDDEN, f"Allowed: {', '.join(self.settings.allowed_namespaces)}.")
        if write and not self.settings.namespace_writable(namespace):
            raise SecureError(Code.NAMESPACE_PROTECTED)

    # -- registration --------------------------------------------------------
    def allowed(self, cls: ToolClass) -> bool:
        return cls is ToolClass.READ or self.settings.writes_enabled

    def topic_allows(self, name: str) -> bool:
        """Is the tool's subject enabled? Every tool must be listed in topics.TOOL_TOPICS."""
        topic = TOOL_TOPICS.get(name)
        if topic is None:
            raise RuntimeError(f"tool {name!r} has no topic in topics.TOOL_TOPICS")
        if topic == WRITES:  # apply/revert exist only if some write tool exists
            return any(c is ToolClass.WRITE for c in self.registered.values())
        return self.settings.topic_enabled(topic)

    def require_kind_topic(self, kind: Any) -> None:
        """Object kinds follow the topic of their catalogue family."""
        if not self.settings.topic_enabled(kind.family):
            raise SecureError(Code.TOPIC_DISABLED, f"Kind {kind.name} belongs to the {kind.family!r} subject.")

    def tool(self, mcp: FastMCP, cls: ToolClass, *, title: str, idempotent: bool = True) -> Callable:
        def decorator(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
            if not self.topic_allows(fn.__name__) or not self.allowed(cls):
                return fn  # not registered: the tool does not exist for the client
            wrapped = self._guarded(fn, cls)
            mcp.tool(
                name=fn.__name__,
                title=title,
                description=inspect.cleandoc(fn.__doc__ or ""),
                annotations=ToolAnnotations(
                    title=title,
                    readOnlyHint=cls is ToolClass.READ,
                    destructiveHint=False,
                    idempotentHint=idempotent,
                    openWorldHint=True,
                ),
            )(wrapped)
            self.registered[fn.__name__] = cls
            return wrapped

        return decorator

    def _guarded(self, fn: Callable[..., Awaitable[Any]], cls: ToolClass) -> Callable[..., Awaitable[Any]]:
        name = fn.__name__

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx: Context | None = kwargs.get("ctx")
            context: dict[str, Any] = {"request_id": f"req_{secrets.token_hex(8)}", "extra": {}}
            audit_token = _audit_ctx.set(context)
            started = time.perf_counter()
            logged_args = {k: v for k, v in kwargs.items() if k != "ctx"}
            digest = args_hash(name, logged_args)
            for key, field in (("namespace", "namespace"), ("name", "target")):
                if isinstance(kwargs.get(key), str):
                    context["extra"][field] = kwargs[key]
            ident: Identity | None = None
            status, code, detail = "ok", None, ""
            token = None
            try:
                if ctx is None:
                    raise SecureError(Code.INTERNAL, detail="no context")
                ident = await self.resolve_identity(ctx)
                token = _current.set(ident)
                self.guardrails.check(identity=ident.key, session=ident.session, tool=name, args_hash=digest)
                return await fn(*args, **kwargs)
            except SecureError as exc:
                status, code, detail = "denied" if exc.status is None else "error", exc.code, exc.detail
                raise
            except Exception as exc:  # pydantic errors, bugs: never leak internals
                status, code, detail = "error", Code.INTERNAL, type(exc).__name__
                raise SecureError(Code.INTERNAL, detail=type(exc).__name__) from exc
            finally:
                self.audit.emit(
                    event="tool_call", request_id=context["request_id"], tool=name, tool_class=str(cls),
                    session=ident.session if ident else None,
                    user=ident.principal.user if ident else None,
                    user_uuid=ident.principal.user_uuid if ident else None,
                    user_type=ident.principal.user_type if ident else None,
                    args_sha256_16=digest, status=status, error_code=str(code) if code else None,
                    detail=detail or None, latency_ms=int((time.perf_counter() - started) * 1000),
                    **context["extra"],
                )
                if token is not None:
                    _current.reset(token)
                _audit_ctx.reset(audit_token)

        return wrapper
