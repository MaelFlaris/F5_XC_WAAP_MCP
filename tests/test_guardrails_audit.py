import json

import pytest

from f5xc_waap_mcp.errors import Code, SecureError
from f5xc_waap_mcp.guardrails import Guardrails
from tests.conftest import TOKEN, FakeXC, Harness, make_settings, result_json


def test_rate_limit_per_identity_and_window():
    rails = Guardrails(make_settings(rate_per_minute=2))
    rails.check(identity="a", session="s", tool="t", args_hash="1", now=0)
    rails.check(identity="a", session="s", tool="t", args_hash="2", now=1)
    with pytest.raises(SecureError) as exc:
        rails.check(identity="a", session="s", tool="t", args_hash="3", now=2)
    assert exc.value.code is Code.RATE_LIMITED
    rails.check(identity="b", session="s2", tool="t", args_hash="3", now=2)
    rails.check(identity="a", session="s", tool="t", args_hash="4", now=62)


def test_global_rate_limit_stops_identity_rotation():
    rails = Guardrails(make_settings(global_rate_per_minute=3))
    for i in range(3):
        rails.check(identity=f"id{i}", session=f"s{i}", tool="t", args_hash="h", now=0)
    with pytest.raises(SecureError):
        rails.check(identity="id9", session="s9", tool="t", args_hash="h", now=0)


def test_loop_detection_and_session_cap():
    rails = Guardrails(make_settings(loop_threshold=3, session_call_cap=5))
    rails.check(identity="a", session="s", tool="t", args_hash="same", now=0)
    rails.check(identity="a", session="s", tool="t", args_hash="same", now=0)
    with pytest.raises(SecureError) as exc:
        rails.check(identity="a", session="s", tool="t", args_hash="same", now=0)
    assert exc.value.code is Code.LOOP_DETECTED
    for i in range(3):
        rails.check(identity="a", session="s", tool="t", args_hash=str(i), now=0)
    with pytest.raises(SecureError) as exc:
        rails.check(identity="a", session="s", tool="t", args_hash="x", now=0)
    assert exc.value.code is Code.SESSION_CAP_REACHED


async def test_audit_log_has_no_token_and_no_argument_values():
    xc = FakeXC()
    xc.add("GET", "/api/config/namespaces/prod/app_firewalls", {"items": []})
    harness = Harness(make_settings(), xc)
    result_json(await harness.call("list_objects", {"kind": "app_firewall", "namespace": "prod",
                                                    "label_filter": "team=secret-value"}))
    await harness.call("list_objects", {"kind": "app_firewall", "namespace": "finance"})
    lines = harness.audit()
    assert [line["status"] for line in lines] == ["ok", "denied"]
    assert lines[1]["error_code"] == "namespace_forbidden"
    raw = json.dumps(lines)
    assert TOKEN not in raw and "secret-value" not in raw
    assert lines[0]["user"] == "alice@example.com" and lines[0]["user_uuid"] == "uuid-alice"
    assert lines[0]["session"].startswith("ses_") and len(lines[0]["args_sha256_16"]) == 16
