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

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

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
        populate_by_name=True,
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
    bind_port: Annotated[int, Field(ge=1024, le=65535, validation_alias="F5XC_MCP_BIND_PORT")] = 8765
    allowed_hosts: Annotated[tuple[str, ...], NoDecode, Field(validation_alias="F5XC_MCP_ALLOWED_HOSTS")] = ()
    allowed_origins: Annotated[tuple[str, ...], NoDecode, Field(validation_alias="F5XC_MCP_ALLOWED_ORIGINS")] = ()

    ca_bundle: Annotated[str | None, Field(validation_alias="F5XC_MCP_CA_BUNDLE")] = None
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
    audit_path: Annotated[str | None, Field(validation_alias="F5XC_MCP_AUDIT_LOG")] = None

    @field_validator("allowed_namespaces", "allowed_hosts", "allowed_origins", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        return _csv(value)

    @field_validator("tenant")
    @classmethod
    def _check_tenant(cls, value: str) -> str:
        if not TENANT_RE.match(value):
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
            if len(namespace) > 63 or not XC_NAME_RE.match(namespace):
                raise ValueError(f"invalid namespace name: {namespace!r}")
        return value

    @field_validator("bind_host")
    @classmethod
    def _check_bind(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("bind host must be an IP address") from exc
        if not address.is_loopback:
            # TLS and client exposure belong to a reverse proxy in front.
            raise ValueError("bind host must be a loopback address; put a TLS reverse proxy in front")
        return value

    @field_validator("api_token")
    @classmethod
    def _check_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not API_TOKEN_RE.match(value.get_secret_value()):
            raise ValueError("F5XC_API_TOKEN has an unexpected format")
        return value

    @model_validator(mode="after")
    def _cross_checks(self) -> Self:
        if self.mode is Mode.WRITE and not self.enable_writes:
            raise ValueError("F5XC_MCP_MODE=write also requires F5XC_MCP_ENABLE_WRITES=true")
        if self.transport is Transport.STDIO and self.api_token is None:
            raise ValueError("stdio transport requires F5XC_API_TOKEN (your personal API token)")
        if self.transport is Transport.STREAMABLE_HTTP and self.api_token is not None:
            raise ValueError(
                "F5XC_API_TOKEN must not be set in HTTP mode: each caller sends its own token "
                "in the X-F5XC-API-Token header"
            )
        return self

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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
