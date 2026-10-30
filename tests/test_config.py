import pytest
from pydantic import ValidationError

from f5xc_waap_mcp.config import Mode, Settings, Transport
from tests.conftest import TOKEN, make_settings


def test_csv_env_parsing(monkeypatch):
    monkeypatch.setenv("F5XC_TENANT", "acme")
    monkeypatch.setenv("F5XC_ALLOWED_NAMESPACES", "prod, staging")
    monkeypatch.setenv("F5XC_API_TOKEN", TOKEN)
    settings = Settings(_env_file=None)
    assert settings.allowed_namespaces == ("prod", "staging")
    assert settings.mode is Mode.READ
    assert settings.base_url == "https://acme.console.ves.volterra.io"


def test_write_mode_requires_explicit_flag():
    with pytest.raises(ValidationError):
        make_settings(mode="write")
    assert make_settings(mode="write", enable_writes=True).writes_enabled
    assert not make_settings(enable_writes=True).writes_enabled  # flag alone does nothing


def test_http_mode_refuses_server_token():
    with pytest.raises(ValidationError, match="must not be set in HTTP mode"):
        make_settings(transport=Transport.STREAMABLE_HTTP)
    assert make_settings(transport=Transport.STREAMABLE_HTTP, api_token=None).api_token is None


def test_stdio_requires_personal_token():
    with pytest.raises(ValidationError):
        make_settings(api_token=None)


@pytest.mark.parametrize("host", ["0.0.0.0", "10.1.2.3", "localhost", "evil.example"])
def test_bind_must_be_loopback(host):
    with pytest.raises(ValidationError):
        make_settings(bind_host=host)


@pytest.mark.parametrize("tenant", ["acme.evil.com", "acme/x", "ACME", "a", "acme@x", ""])
def test_tenant_validation(tenant):
    with pytest.raises(ValidationError):
        make_settings(tenant=tenant)


@pytest.mark.parametrize("namespaces", [(), ("Prod",), ("../system",), ("a" * 64,)])
def test_namespace_allowlist_validation(namespaces):
    with pytest.raises(ValidationError):
        make_settings(allowed_namespaces=namespaces)


def test_protected_namespaces_never_writable():
    settings = make_settings(allowed_namespaces=("prod", "shared", "system"))
    assert settings.namespace_writable("prod")
    assert not settings.namespace_writable("shared")
    assert not settings.namespace_writable("system")
    assert not settings.namespace_writable("other")


def test_non_loopback_bind_needs_flag_http_and_host_allowlist():
    base = {"bind_host": "0.0.0.0", "transport": Transport.STREAMABLE_HTTP, "api_token": None}
    with pytest.raises(ValidationError):
        make_settings(**base, allowed_hosts=("mcp.example.com",))
    with pytest.raises(ValidationError):
        make_settings(**base, allow_non_loopback_bind=True)
    with pytest.raises(ValidationError):
        make_settings(bind_host="0.0.0.0", allow_non_loopback_bind=True, allowed_hosts=("mcp.example.com",))
    settings = make_settings(**base, allow_non_loopback_bind=True, allowed_hosts=("mcp.example.com",))
    assert settings.bind_host == "0.0.0.0"
