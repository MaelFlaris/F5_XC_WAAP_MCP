"""Nominative identity of the caller, resolved from F5 XC itself.

The API token is sent to ``GET /api/web/custom/namespaces/system/whoami``
(documented in the ``user`` API: "fetches user information based on the
username header from the request context"). The answer gives the user name,
e-mail, UUID and account type; that is what the audit log and the per-user
quotas use, so a token rotation does not change the identity.

Validation happens before any quota is consumed, with:
  * a positive cache (``F5XC_MCP_IDENTITY_CACHE_TTL_S``) keyed by a hash of the token;
  * a negative cache (60 s) so a bad token is not re-sent to XC on every call;
  * a global limit on uncached validations (``F5XC_MCP_AUTH_RATE_PER_MINUTE``),
    so random tokens cannot be used to hammer XC or exhaust the user quotas.
Per-IP limiting of anonymous clients belongs to the reverse proxy.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any

from pydantic import SecretStr

from . import catalog
from .config import Settings
from .errors import Code, SecureError
from .sanitize import text
from .xc_client import XCClient

NEGATIVE_TTL_S = 60.0
MAX_CACHE = 2048
WINDOW_S = 60.0


@dataclass(frozen=True)
class Principal:
    user: str  # e-mail when available, else the XC user name
    user_uuid: str
    user_type: str  # USER | SERVICE

    @property
    def key(self) -> str:
        return f"user:{self.user_uuid or self.user}"


class IdentityResolver:
    def __init__(self, settings: Settings, client: XCClient) -> None:
        self._settings = settings
        self._client = client
        self._cache: OrderedDict[str, tuple[float, Principal | None]] = OrderedDict()
        self._attempts: deque[float] = deque()
        self._lock = threading.Lock()

    @staticmethod
    def _cache_key(token: SecretStr) -> str:
        return hashlib.sha256(token.get_secret_value().encode()).hexdigest()

    def _cached(self, key: str, now: float) -> tuple[bool, Principal | None]:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None or entry[0] < now:
                self._cache.pop(key, None)
                return False, None
            self._cache.move_to_end(key)
            return True, entry[1]

    def _store(self, key: str, principal: Principal | None, now: float) -> None:
        ttl = self._settings.identity_cache_ttl_s if principal else NEGATIVE_TTL_S
        with self._lock:
            self._cache[key] = (now + ttl, principal)
            while len(self._cache) > MAX_CACHE:
                self._cache.popitem(last=False)

    def _count_attempt(self, now: float) -> None:
        with self._lock:
            while self._attempts and now - self._attempts[0] > WINDOW_S:
                self._attempts.popleft()
            if len(self._attempts) >= self._settings.auth_rate_per_minute:
                raise SecureError(Code.AUTH_RATE_LIMITED)
            self._attempts.append(now)

    async def resolve(self, token: SecretStr) -> Principal:
        now = time.monotonic()
        key = self._cache_key(token)
        hit, principal = self._cached(key, now)
        if hit:
            if principal is None:
                raise SecureError(Code.UNAUTHENTICATED, "Token rejected by F5 XC.")
            return principal
        self._count_attempt(now)
        method, path = catalog.data_path("identity.whoami", namespace="system")
        try:
            payload = await self._client.request(method, path, token)
        except SecureError as exc:
            if exc.status == 401:
                # The token itself is rejected: cache the refusal.
                self._store(key, None, now)
                raise SecureError(Code.UNAUTHENTICATED, "Token rejected by F5 XC.", detail=exc.detail,
                                  status=401) from exc
            if exc.status == 403:
                # Token possibly valid but its role cannot read namespaces/system/whoami
                # (e.g. a role limited to application namespaces). Not cached: fixing the
                # role must take effect immediately. See docs/UNCERTAINTIES.md.
                raise SecureError(Code.IDENTITY_UNAVAILABLE,
                                  "F5 XC answered 403 on whoami: check that the user's role allows it "
                                  "(run 'f5xc-waap-mcp check').", detail=exc.detail, status=403) from exc
            raise
        principal = self._principal(payload)
        self._store(key, principal, now)
        return principal

    def _principal(self, payload: Any) -> Principal:
        if not isinstance(payload, dict):
            raise SecureError(Code.IDENTITY_UNAVAILABLE, detail="whoami: unexpected payload")
        user = text(payload.get("email") or payload.get("name"), 254)
        user_type = text(payload.get("type") or "USER", 20)
        if not user:
            # e.g. whoami answers for a console session but not for an API token
            raise SecureError(Code.IDENTITY_UNAVAILABLE, detail="whoami: no user name or e-mail")
        if payload.get("disabled") is True or payload.get("state") in ("StateDisabled", "StateCreateFailed"):
            raise SecureError(Code.UNAUTHENTICATED, "The F5 XC user is disabled.")
        if user_type == "SERVICE" and not self._settings.allow_service_credentials:
            raise SecureError(Code.UNAUTHENTICATED, "Service credentials are refused: use a personal API token.")
        if user_type not in ("USER", "SERVICE"):
            raise SecureError(Code.UNAUTHENTICATED, detail=f"whoami: account type {user_type}")
        return Principal(user=user, user_uuid=text(payload.get("user_uuid"), 64), user_type=user_type)
