"""Read tools not exercised elsewhere (audit F-11: branch coverage of security.py and
config_read.py was 72 % / 71 %). Untrusted values are injected where they flow."""

import json

import pytest

from f5xc_waap_mcp.tools.security import assess_http_lb
from tests.conftest import error_text, result_json

TAGS = "".join(chr(0xE0000 + ord(c)) for c in "obey")
NS = "/api/data/namespaces/prod"


@pytest.mark.parametrize(("choice", "check", "severity"), [
    ({"loadbalancer_type": {"choice": "http", "configured": True}}, "no_tls", "medium"),
    ({"ip_reputation_choice": "disable_ip_reputation"}, "ip_reputation_disabled", "medium"),
    ({"malicious_user_detection_choice": "disable_malicious_user_detection"}, "malicious_user_detection_disabled",
     "low"),
    ({"rate_limit_choice": "disable_rate_limit"}, "rate_limit_disabled", "low"),
    ({"service_policy_choice": "no_service_policies"}, "no_service_policies", "low"),
    ({"api_discovery_choice": "disable_api_discovery"}, "api_discovery_disabled", "low"),
    ({"client_side_defense_choice": "disable_client_side_defense"}, "client_side_defense_disabled", "info"),
    ({"threat_mesh_choice": "disable_threat_mesh"}, "threat_mesh_disabled", "info"),
    ({"waf_choice": "disable_waf"}, "waf_disabled", "high"),
])
def test_posture_findings_per_choice(choice, check, severity):
    findings = assess_http_lb({"choices": choice}, {}, None)
    assert {"severity": severity, "check": check} == {k: findings[0][k] for k in ("severity", "check")}


def test_posture_flags_waf_skip_rules():
    spec = {"waf_exclusion": {"waf_exclusion_inline_rules": {"rules": [{"waf_skip_processing": {}}, {}]}}}
    assert any(f["check"] == "waf_skip_rules" for f in assess_http_lb({"choices": {}}, spec, "blocking"))


async def test_list_supported_kinds_and_namespaces(harness, xc):
    kinds = result_json(await harness.call("list_supported_kinds"))
    assert "waf" in kinds["data"] and kinds["writes_enabled"] is False
    xc.add("GET", "/api/web/namespaces", {"items": [{"name": "prod"}, {"name": "secret-team"}, {"name": "staging"}]})
    names = result_json(await harness.call("list_namespaces"))["data"]
    assert names == ["prod", "staging"]  # only allow-listed namespaces are revealed


async def test_list_objects_label_filter_and_truncation(xc):
    from tests.conftest import Harness, make_settings
    harness = Harness(make_settings(max_items=2), xc)
    xc.add("GET", "/api/config/namespaces/prod/origin_pools", {"items": [{"name": f"p{i}"} for i in range(5)]})
    data = result_json(await harness.call("list_objects", {"kind": "origin_pool", "namespace": "prod",
                                                           "label_filter": "env in (prod)"}))
    assert data["truncated"] is True and len(data["data"]) == 2 and data["count"] == 5
    assert xc.api_requests[-1].url.params["label_filter"] == "env in (prod)"
    assert (await harness.call("list_objects", {"kind": "origin_pool", "namespace": "prod",
                                                "label_filter": "x\"; drop"})).isError


async def test_get_object_referrers_view(harness, xc):
    xc.add("GET", "/api/config/namespaces/prod/app_firewalls/fw1", {
        "metadata": {"name": "fw1", "namespace": "prod"},
        "referring_objects": [{"kind": "http_loadbalancer", "name": "shop", "namespace": "prod"},
                              {"kind": "x" + TAGS, "name": "lb2", "namespace": "prod"}]})
    data = result_json(await harness.call("get_object", {"kind": "app_firewall", "namespace": "prod", "name": "fw1",
                                                         "view": "referrers"}))["data"]
    assert data["referring_objects"][0] == {"kind": "http_loadbalancer", "name": "shop", "namespace": "prod"}
    assert data["referring_objects"][1]["kind"] == "x"
    assert xc.api_requests[-1].url.params["response_format"] == "GET_RSP_FORMAT_REFERRING_OBJECTS"


async def test_active_service_policies(harness, xc):
    xc.add("GET", "/api/config/namespaces/prod/active_service_policies",
           {"service_policies": [{"name": "deny-bad", "namespace": "prod"}, "garbage"]})
    data = result_json(await harness.call("get_active_service_policies", {"namespace": "prod"}))["data"]
    assert data == [{"name": "deny-bad", "namespace": "prod"}]


@pytest.mark.parametrize(("tool", "path", "key", "extra"), [
    ("query_security_incidents", "/app_security/incidents", "incidents", {}),
    ("query_suspicious_users", "/app_security/suspicious_user_logs", "logs", {}),
    ("query_access_logs", "/access_logs", "logs", {"filters": [{"field": "rsp_code", "op": "=~", "value": "5.*"}]}),
    ("query_audit_logs", "/audit_logs", "logs", {"filters": [{"field": "user", "value": "bob@example.com"}]}),
])
async def test_log_tools_project_and_sanitise(harness, xc, tool, path, key, extra):
    record = {"time": "2026-10-30T10:00:00Z", "src_ip": "198.51.100.1", "req_path": "/x" + TAGS,
              "method": "POST", "user": "bob@example.com", "req_body": "password=hunter2", "rsp_code": "500"}
    xc.add("POST", NS + path, {key: [json.dumps(record), "not json"], "total_hits": "2"})
    data = result_json(await harness.call(tool, {"namespace": "prod", **extra}))
    rows = data["data"]
    assert rows[0]["req_path"] == "/x" and "req_body" not in rows[0] and rows[1] == {"unparsed": True}
    body = xc.bodies(NS + path)[0]
    assert body["namespace"] == "prod" and body["scroll"] is False
    if extra:
        field = extra["filters"][0]
        assert body["query"] == f'{{{field["field"]}{field.get("op", "=")}"{field["value"]}"}}'


async def test_aggregate_access_logs(harness, xc):
    xc.add("POST", NS + "/access_logs/aggregation", {"aggs": {"top": {"field_aggregation": {"buckets": [
        {"key": "404", "count": "12"}]}}}})
    data = result_json(await harness.call("aggregate_access_logs", {"namespace": "prod", "group_by": "RSP_CODE"}))
    assert data["data"] == [{"key": "404", "count": "12"}]
    xc.add("POST", NS + "/access_logs/aggregation", {"aggs": "unexpected"})
    assert result_json(await harness.call("aggregate_access_logs", {"namespace": "prod", "group_by": "SRC_IP",
                                                                    "top_k": 3}))["data"] == []


async def test_dos_rules_dns_info_and_signatures(harness, xc):
    lb = "/api/config/namespaces/prod/http_loadbalancers/shop"
    xc.add("GET", lb + "/dos_automitigation_rules", {"dos_automitigation_rules": [
        {"name": "r1", "item": {"ip_prefixes": ["203.0.113.0/24"]}, "private_key": "k"}, "junk"]})
    rules = result_json(await harness.call("get_lb_dos_mitigation_rules", {"namespace": "prod", "name": "shop"}))
    assert rules["data"] == [{"name": "r1", "item": {"ip_prefixes": ["203.0.113.0/24"]}, "private_key": "[redacted]"}]
    xc.add("GET", lb + "/get-dns-info", {"dns_info": {"host_name": "ves-io-abc.ac.vh.ves.io"}})
    dns = result_json(await harness.call("get_lb_dns_info", {"namespace": "prod", "name": "shop"}))
    assert dns["data"]["dns_info"]["host_name"] == "ves-io-abc.ac.vh.ves.io"
    xc.add("GET", "/api/waf/latest-signatures-version", {"version": "2026.10.29" + TAGS})
    version = result_json(await harness.call("get_waf_signatures_version"))
    assert version["data"] == {"version": "2026.10.29"}


async def test_audit_namespace_reports_per_lb_errors(harness, xc):
    xc.add("GET", "/api/config/namespaces/prod/http_loadbalancers", {"items": [{"name": "broken"}, {"oops": 1}]})
    xc.add("GET", "/api/config/namespaces/prod/http_loadbalancers/broken", (403, {}))
    data = result_json(await harness.call("audit_namespace_security", {"namespace": "prod"}))
    assert data["load_balancers"] == 1 and data["data"] == [{"name": "broken", "error": "upstream_forbidden"}]


@pytest.mark.parametrize(("tool", "args", "route"), [
    ("list_objects", {"kind": "origin_pool", "namespace": "prod"}, ("GET", "/api/config/namespaces/prod/origin_pools")),
    ("get_object", {"kind": "origin_pool", "namespace": "prod", "name": "p"},
     ("GET", "/api/config/namespaces/prod/origin_pools/p")),
    ("get_lb_security_posture", {"namespace": "prod", "name": "shop"},
     ("GET", "/api/config/namespaces/prod/http_loadbalancers/shop")),
    ("query_security_events", {"namespace": "prod"}, ("POST", NS + "/app_security/events")),
])
async def test_unexpected_response_shapes_are_errors(harness, xc, tool, args, route):
    xc.add(*route, {"items": "not-a-list"} if tool == "list_objects" else ["not", "an", "object"])
    assert "response_invalid" in error_text(await harness.call(tool, args))
