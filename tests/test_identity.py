"""Nominative identity (whoami) and token validation before quotas."""

import os
import stat

from pydantic import SecretStr

from f5xc_waap_mcp.audit import AuditLog
from f5xc_waap_mcp.errors import SecureError
from tests.conftest import WHOAMI, FakeXC, Harness, error_text, make_settings, result_json

BAD = "ForgedTokenForgedToken-0000"


def harness_with_token(token: str, **settings) -> tuple[Harness, FakeXC]:
    xc = FakeXC()
    xc.add("GET", "/api/config/namespaces/prod/app_firewalls", {"items": []})
    return Harness(make_settings(api_token=token, **settings), xc), xc


async def test_identity_is_resolved_once_and_cached():
    harness, xc = harness_with_token(make_settings().api_token.get_secret_value())
    async with harness.session() as session:
        for _ in range(3):
            assert not (await session.call_tool("list_objects", {"kind": "app_firewall", "namespace": "prod",
                                                                  "label_filter": f"x={_}"})).isError
    assert len([r for r in xc.requests if r.url.path == WHOAMI]) == 1
    assert {line["user"] for line in harness.audit()} == {"alice@example.com"}


async def test_rejected_token_is_negatively_cached_and_uses_no_quota():
    harness, xc = harness_with_token(BAD, rate_per_minute=1)
    async with harness.session() as session:
        for _ in range(3):
            result = await session.call_tool("list_objects", {"kind": "app_firewall", "namespace": "prod"})
            assert "unauthenticated" in error_text(result)
    assert len(xc.requests) == 1  # one whoami, then the negative cache
    assert xc.api_requests == []


async def test_validation_attempts_are_rate_limited():
    xc = FakeXC()
    harness = Harness(make_settings(auth_rate_per_minute=2), xc)
    codes = []
    for i in range(4):
        try:
            await harness.runtime.identities.resolve(SecretStr(f"RandomTokenNumber-{i:010d}"))
        except SecureError as exc:
            codes.append(str(exc.code))
    assert codes == ["unauthenticated", "unauthenticated", "auth_rate_limited", "auth_rate_limited"]
    assert len(xc.requests) == 2


async def test_service_credentials_refused_by_default():
    harness, xc = harness_with_token("ServiceCredentialToken-000001")
    xc.users["ServiceCredentialToken-000001"] = {"name": "svc-ci", "type": "SERVICE", "user_uuid": "u-svc"}
    result = await harness.call("list_objects", {"kind": "app_firewall", "namespace": "prod"})
    assert "personal API token" in error_text(result)
    allowed, xc2 = harness_with_token("ServiceCredentialToken-000001", allow_service_credentials=True)
    xc2.users["ServiceCredentialToken-000001"] = {"name": "svc-ci", "type": "SERVICE", "user_uuid": "u-svc"}
    result_json(await allowed.call("list_objects", {"kind": "app_firewall", "namespace": "prod"}))
    assert allowed.audit()[-1]["user_type"] == "SERVICE"


async def test_disabled_user_refused():
    harness, xc = harness_with_token("DisabledUserToken-0000000001")
    xc.users["DisabledUserToken-0000000001"] = {"name": "bob", "disabled": True, "type": "USER"}
    assert "unauthenticated" in error_text(await harness.call("list_objects", {"kind": "app_firewall",
                                                                                "namespace": "prod"}))


async def test_sessions_get_distinct_random_ids():
    harness, _ = harness_with_token(make_settings().api_token.get_secret_value())
    await harness.call("list_objects", {"kind": "app_firewall", "namespace": "prod"})
    await harness.call("list_objects", {"kind": "app_firewall", "namespace": "prod"})
    sessions = [line["session"] for line in harness.audit()]
    assert len(set(sessions)) == 2 and all(s.startswith("ses_") and len(s) == 36 for s in sessions)


def test_audit_file_is_private_and_survives_rotation(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    os.chmod(path, 0o644)
    log = AuditLog(str(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    log.emit(event="one")
    os.rename(path, tmp_path / "audit.jsonl.1")  # logrotate
    log.emit(event="two")
    assert "two" in path.read_text() and "one" in (tmp_path / "audit.jsonl.1").read_text()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


async def test_whoami_403_is_identity_unavailable_and_not_cached():
    harness, xc = harness_with_token("LimitedRoleToken-0000000001")
    xc.add("GET", WHOAMI, (403, {"message": "forbidden"}))
    for _ in range(2):
        text = error_text(await harness.call("list_objects", {"kind": "app_firewall", "namespace": "prod"}))
        assert "identity_unavailable" in text and "f5xc-waap-mcp check" in text
    assert len([r for r in xc.requests if r.url.path == WHOAMI]) == 2  # not negatively cached
    assert xc.api_requests == []


async def test_whoami_without_user_is_identity_unavailable():
    harness, xc = harness_with_token("SessionOnlyToken-00000000001")
    xc.users["SessionOnlyToken-00000000001"] = {"type": "USER"}
    assert "identity_unavailable" in error_text(await harness.call("list_objects", {
        "kind": "app_firewall", "namespace": "prod"}))


async def test_check_command_reports_identity_and_namespace_access():
    import httpx

    from f5xc_waap_mcp.check import run_check
    from f5xc_waap_mcp.xc_client import XCClient

    xc = FakeXC()
    xc.add("GET", "/api/config/namespaces/prod/http_loadbalancers", {"items": [{"name": "a"}, {"name": "b"}]})
    xc.add("GET", "/api/config/namespaces/prod/active_service_policies", {"service_policies": []})
    xc.add("GET", "/api/config/namespaces/staging/http_loadbalancers", (403, {}))
    settings = make_settings(allowed_namespaces=("prod", "staging"))
    report = await run_check(settings, XCClient(settings, transport=httpx.MockTransport(xc.handler)))
    assert report["ok"] is True
    assert report["identity"]["user"] == "alice@example.com"
    assert set(report["identity"]["whoami_fields_present"]) >= {"email", "user_uuid", "type"}
    assert report["namespaces"]["prod"]["list_http_loadbalancers"] == {"ok": True, "count": 2}
    assert report["namespaces"]["staging"]["list_http_loadbalancers"]["http_status"] == 403
    assert make_settings().api_token.get_secret_value() not in str(report)


async def test_check_command_fails_when_whoami_is_forbidden():
    import httpx

    from f5xc_waap_mcp.check import run_check
    from f5xc_waap_mcp.xc_client import XCClient

    xc = FakeXC()
    xc.add("GET", WHOAMI, (403, {}))
    settings = make_settings(allowed_namespaces=("prod",))
    report = await run_check(settings, XCClient(settings, transport=httpx.MockTransport(xc.handler)))
    assert report["ok"] is False and report["identity"]["http_status"] == 403
