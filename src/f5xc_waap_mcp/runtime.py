"""Shared runtime: identity resolution, tool registration by class, and the
single control chain every tool goes through:

    identity -> guardrails -> tool body -> audit (success or failure)

Tools are registered with FastMCP only when their class is allowed by the
configuration: in read mode, write tools do not exist in ``tools/list``.
"""

from __future__ import annotations

import functools
import inspect
import secrets
import time
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import SecretStr

from .audit import AuditLog, args_hash, pseudonym
from .config import API_TOKEN_RE, Settings, Transport
from .errors import Code, SecureError
from .guardrails import Guardrails
from .plans import PlanStore
from .xc_client import XCClient

TOKEN_HEADER = "x-f5xc-api-token"  # noqa: S105 - header name, not a secret


class ToolClass(StrEnum):
    READ = "read"
    WRITE = "write"


@dataclass(frozen=True)
class Identity:
    key: str  # pseudonymous, stable per token
    token: SecretStr
    session: str


_current: ContextVar[Identity | None] = ContextVar("f5xc_identity", default=None)


class Runtime:
    def __init__(self, settings: Settings, client: XCClient | None = None, audit: AuditLog | None = None) -> None:
        self.settings = settings
        self.client = client or XCClient(settings)
        self.guardrails = Guardrails(settings)
        self.audit = audit or AuditLog(settings.audit_path)
        self.plans = PlanStore(settings.plan_ttl_s)
        self.registered: dict[str, ToolClass] = {}

    # -- identity ------------------------------------------------------------
    def resolve_identity(self, ctx: Context) -> Identity:
        session = f"s{id(ctx.request_context.session):x}"  # server-side object, not a client header
        if self.settings.transport is Transport.STDIO:
            token = self.settings.api_token
            if token is None:
                raise SecureError(Code.UNAUTHENTICATED)
            return Identity(f"stdio:{pseudonym(token.get_secret_value())}", token, session)
        request = ctx.request_context.request
        headers = getattr(request, "headers", None)
        raw = headers.get(TOKEN_HEADER) if headers is not None else None
        if not raw or not API_TOKEN_RE.match(raw.strip()):
            raise SecureError(Code.UNAUTHENTICATED, "Send your personal F5 XC API token in X-F5XC-API-Token.")
        token = SecretStr(raw.strip())
        return Identity(f"token:{pseudonym(token.get_secret_value())}", token, session)

    @staticmethod
    def identity() -> Identity:
        ident = _current.get()
        if ident is None:
            raise SecureError(Code.UNAUTHENTICATED)
        return ident

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

    def tool(self, mcp: FastMCP, cls: ToolClass, *, title: str, idempotent: bool = True) -> Callable:
        def decorator(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
            if not self.allowed(cls):
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
            request_id = f"req_{secrets.token_hex(6)}"
            started = time.perf_counter()
            logged_args = {k: v for k, v in kwargs.items() if k != "ctx"}
            digest = args_hash(name, logged_args)
            namespace = kwargs.get("namespace")
            identity_key = "-"
            status, code, detail = "ok", None, ""
            token = None
            try:
                if ctx is None:
                    raise SecureError(Code.INTERNAL, detail="no context")
                ident = self.resolve_identity(ctx)
                identity_key = ident.key
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
                if token is not None:
                    _current.reset(token)
                self.audit.emit(
                    request_id=request_id, identity=identity_key, tool=name, tool_class=str(cls),
                    args_sha256_16=digest, namespace=namespace if isinstance(namespace, str) else None,
                    target=kwargs.get("name") if isinstance(kwargs.get("name"), str) else None,
                    status=status, error_code=str(code) if code else None, detail=detail or None,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                )

        return wrapper
