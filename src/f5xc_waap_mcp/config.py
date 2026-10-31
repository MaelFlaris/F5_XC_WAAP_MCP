"""Server configuration, read once from the environment and frozen.

Safety properties enforced here (startup fails otherwise):
  * the XC console URL is built only from a validated tenant name;
  * at least one namespace must be allow-listed; protected namespaces can never
    be written;
  * write mode needs both ``F5XC_MCP_MODE=write`` and ``F5XC_MCP_ENABLE_WRITES=true``;
  * in HTTP mode the server holds no XC token of its own (``F5XC_API_TOKEN``
    is refused) and binds to loopback only.
"""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .topics import resolve_topics

XC_DOMAIN_SUFFIX = ".console.ves.volterra.io"
XC_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$")
API_TOKEN_RE = re.compile(r"^[A-Za-z0-9._+/=\-]{16,4096}$")

# Namespaces that are never writable, whatever the configuration says.
PROTECTED_NAMESPACES = frozenset({"system", "shared", "ves-io-shared"})


class Mode(StrEnum):
    READ = "read"
    WRITE = "write"


class Transport(StrEnum):
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"


def _csv(value: object) -> object:
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=None,
        case_sensitive=False,
        frozen=True,
        # Only the F5XC_* names are read. With populate_by_name the environment was
        # also searched by field name, so generic variables such as MODE=write,
        # ENABLE_WRITES=true or API_TOKEN configured the server (audit F-15).
        populate_by_name=False,
        extra="ignore",
    )

    tenant: Annotated[str, Field(validation_alias="F5XC_TENANT")]
    mode: Annotated[Mode, Field(validation_alias="F5XC_MCP_MODE")] = Mode.READ
    enable_writes: Annotated[bool, Field(validation_alias="F5XC_MCP_ENABLE_WRITES")] = False
    allowed_namespaces: Annotated[tuple[str, ...], NoDecode, Field(validation_alias="F5XC_ALLOWED_NAMESPACES")]
    transport: Annotated[Transport, Field(validation_alias="F5XC_MCP_TRANSPORT")] = Transport.STDIO

    # stdio only: the personal token of the user who launches the server.
    api_token: Annotated[SecretStr | None, Field(validation_alias="F5XC_API_TOKEN")] = None

    bind_host: Annotated[str, Field(validation_alias="F5XC_MCP_BIND_HOST")] = "127.0.0.1"
    # Containers: binding outside loopback needs this flag AND an explicit Host allow-list.
    allow_non_loopback_bind: Annotated[bool, Field(validation_alias="F5XC_MCP_ALLOW_NON_LOOPBACK_BIND")] = False
    bind_port: Annotated[int, Field(ge=1024, le=65535, validation_alias="F5XC_MCP_BIND_PORT")] = 8765
    allowed_hosts: Annotated[tuple[str, ...], NoDecode, Field(validation_alias="F5XC_MCP_ALLOWED_HOSTS")] = ()
    allowed_origins: Annotated[tuple[str, ...], NoDecode, Field(validation_alias="F5XC_MCP_ALLOWED_ORIGINS")] = ()

    ca_bundle: Annotated[str | None, Field(validation_alias="F5XC_MCP_CA_BUNDLE")] = None
    # Explicit outbound proxy for the XC API (HTTPS_PROXY is not read: the client
    # uses a dedicated transport). No credentials in the URL.
    https_proxy: Annotated[str | None, Field(validation_alias="F5XC_MCP_HTTPS_PROXY")] = None
    request_timeout_s: Annotated[float, Field(gt=0, le=120, validation_alias="F5XC_MCP_TIMEOUT_S")] = 20.0
    max_response_bytes: Annotated[
        int, Field(ge=16_384, le=33_554_432, validation_alias="F5XC_MCP_MAX_RESPONSE_BYTES")
    ] = 8_388_608
    max_items: Annotated[int, Field(ge=1, le=1000, validation_alias="F5XC_MCP_MAX_ITEMS")] = 200
    max_events: Annotated[int, Field(ge=1, le=500, validation_alias="F5XC_MCP_MAX_EVENTS")] = 100
    max_query_window_h: Annotated[int, Field(ge=1, le=720, validation_alias="F5XC_MCP_MAX_QUERY_WINDOW_H")] = 168

    rate_per_minute: Annotated[int, Field(ge=1, le=1000, validation_alias="F5XC_MCP_RATE_PER_MINUTE")] = 60
    global_rate_per_minute: Annotated[
        int, Field(ge=1, le=10_000, validation_alias="F5XC_MCP_GLOBAL_RATE_PER_MINUTE")
    ] = 300
    session_call_cap: Annotated[int, Field(ge=1, le=100_000, validation_alias="F5XC_MCP_SESSION_CALL_CAP")] = 1000
    loop_threshold: Annotated[int, Field(ge=2, le=100, validation_alias="F5XC_MCP_LOOP_THRESHOLD")] = 5

    plan_ttl_s: Annotated[int, Field(ge=30, le=900, validation_alias="F5XC_MCP_PLAN_TTL_S")] = 300
    min_ipv4_prefix_len: Annotated[int, Field(ge=8, le=32, validation_alias="F5XC_MCP_MIN_IPV4_PREFIX_LEN")] = 16
    # Subjects enabled (see topics.py): "all", "waf,posture", "all,-dns".
    topics: Annotated[tuple[str, ...], NoDecode, Field(validation_alias="F5XC_MCP_TOPICS")] = ("all",)
    # Operations: while this file exists every write tool refuses (no restart needed).
    write_kill_switch: Annotated[str | None, Field(validation_alias="F5XC_MCP_WRITE_KILL_SWITCH")] = None
    # Operations: directory where the pre-change state of each applied replace is
    # kept (0700 dir, 0600 files) so that plan_revert can build a reviewed inverse plan.
    rollback_dir: Annotated[str | None, Field(validation_alias="F5XC_MCP_ROLLBACK_DIR")] = None

    # Identity: tokens are validated against XC (whoami) before any quota is used.
    identity_cache_ttl_s: Annotated[int, Field(ge=30, le=900, validation_alias="F5XC_MCP_IDENTITY_CACHE_TTL_S")] = 300
    auth_rate_per_minute: Annotated[int, Field(ge=1, le=600, validation_alias="F5XC_MCP_AUTH_RATE_PER_MINUTE")] = 30
    allow_service_credentials: Annotated[
        bool, Field(validation_alias="F5XC_MCP_ALLOW_SERVICE_CREDENTIALS")
    ] = False
    audit_path: Annotated[str | None, Field(validation_alias="F5XC_MCP_AUDIT_LOG")] = None

    @field_validator("topics", mode="before")
    @classmethod
    def _split_topics(cls, value: object) -> object:
        return _csv(value)

    @field_validator("topics")
    @classmethod
    def _check_topics(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        resolve_topics(value)  # unknown names fail at startup
        return value

    @field_validator("allowed_namespaces", "allowed_hosts", "allowed_origins", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        return _csv(value)

    @field_validator("https_proxy")
    @classmethod
    def _check_proxy(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("F5XC_MCP_HTTPS_PROXY must be an http:// or https:// URL")
        if parts.username or parts.password:
            raise ValueError("F5XC_MCP_HTTPS_PROXY must not embed credentials")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ValueError("F5XC_MCP_HTTPS_PROXY must be scheme://host[:port]")
        return value

    @field_validator("tenant")
    @classmethod
    def _check_tenant(cls, value: str) -> str:
        if not TENANT_RE.fullmatch(value):
            raise ValueError("invalid tenant name (expected the short tenant id, e.g. 'acme-corp')")
        return value

    @field_validator("allowed_namespaces")
    @classmethod
    def _check_namespaces(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("at least one namespace must be allow-listed")
        if len(value) > 100:
            raise ValueError("namespace allow-list too large")
        for namespace in value:
            if len(namespace) > 63 or not XC_NAME_RE.fullmatch(namespace):
                raise ValueError(f"invalid namespace name: {namespace!r}")
        return value

    @field_validator("bind_host")
    @classmethod
    def _check_bind(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("bind host must be an IP address") from exc
        return str(address)

    @field_validator("api_token")
    @classmethod
    def _check_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not API_TOKEN_RE.fullmatch(value.get_secret_value()):
            raise ValueError("F5XC_API_TOKEN has an unexpected format")
        return value

    @model_validator(mode="after")
    def _cross_checks(self) -> Self:
        if self.mode is Mode.WRITE and not self.enable_writes:
            raise ValueError("F5XC_MCP_MODE=write also requires F5XC_MCP_ENABLE_WRITES=true")
        if self.transport is Transport.STDIO and self.api_token is None:
            raise ValueError("stdio transport requires F5XC_API_TOKEN (your personal API token)")
        if not ipaddress.ip_address(self.bind_host).is_loopback:
            # TLS and client exposure belong to a reverse proxy in front.
            if not self.allow_non_loopback_bind:
                raise ValueError("bind host must be loopback unless F5XC_MCP_ALLOW_NON_LOOPBACK_BIND=true")
            if self.transport is not Transport.STREAMABLE_HTTP or not self.allowed_hosts:
                raise ValueError("a non-loopback bind requires HTTP transport and F5XC_MCP_ALLOWED_HOSTS")
        if self.transport is Transport.STREAMABLE_HTTP and self.api_token is not None:
            raise ValueError(
                "F5XC_API_TOKEN must not be set in HTTP mode: each caller sends its own token "
                "in the X-F5XC-API-Token header"
            )
        return self

    @property
    def enabled_topics(self) -> frozenset[str]:
        return resolve_topics(self.topics)

    def topic_enabled(self, topic: str) -> bool:
        return topic in self.enabled_topics

    @property
    def writes_enabled(self) -> bool:
        return self.mode is Mode.WRITE and self.enable_writes

    @property
    def base_url(self) -> str:
        return f"https://{self.tenant}{XC_DOMAIN_SUFFIX}"

    def namespace_allowed(self, namespace: str) -> bool:
        return namespace in self.allowed_namespaces

    def namespace_writable(self, namespace: str) -> bool:
        return self.namespace_allowed(namespace) and namespace not in PROTECTED_NAMESPACES


def settings_from_fields(**values: object) -> Settings:
    """Build Settings from field names (code and tests), mapped to their F5XC_* aliases;
    the environment still fills the fields not given."""
    aliases = {name: field.validation_alias for name, field in Settings.model_fields.items()}
    unknown = set(values) - set(aliases)
    if unknown:
        raise TypeError(f"unknown settings: {sorted(unknown)}")
    return Settings(**{str(aliases[name]): value for name, value in values.items()})  # type: ignore[arg-type]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
