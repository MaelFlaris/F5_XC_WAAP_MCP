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


# --- pages added after review: WAF rule hits, alerts, service policy sets ---------------
async def test_waf_rule_hits_totals_sorted_and_sanitised(harness, xc):
    path = NS + "/wafs/metrics/server/rule_hits"
    xc.add("POST", path, {"data": [
        {"id": {"rule_id": "200001234", "virtual_host": "shop"}, "metric": [{"value": "3"}, {"value": "4"}]},
        {"id": {"rule_id": "200009999" + TAGS, "virtual_host": "api"}, "metric": [{"value": "41"}]},
        {"id": {"rule_id": "x"}, "metric": [{"value": "NaN"}, {"value": "abc"}, {}]},
        "junk",
    ]})
    data = result_json(await harness.call("get_waf_rule_hits", {
        "namespace": "prod", "start": "2h", "filters": [{"label": "VIRTUAL_HOST", "op": "NEQ", "value": "internal"}]}))
    rows = data["data"]
    assert [r["hits"] for r in rows] == [41.0, 7.0, 0.0]
    assert rows[0]["labels"]["rule_id"] == "200009999"
    body = xc.bodies(path)[0]
    assert body["group_by"] == ["RULE_ID", "VIRTUAL_HOST"] and body["step"] == body["range"] == "120m"
    assert body["label_filter"] == [{"label": "VIRTUAL_HOST", "op": "NEQ", "value": "internal"}]


@pytest.mark.parametrize("args", [
    {"filters": [{"label": "VIRTUAL_HOST", "value": "shop\n"}]},
    {"filters": [{"label": "PASSWORD", "value": "x"}]},
    {"group_by": ["RULE_ID", "SECRET"]},
    {"group_by": []},
])
async def test_waf_rule_hits_rejects_bad_arguments(harness, xc, args):
    assert (await harness.call("get_waf_rule_hits", {"namespace": "prod", **args})).isError
    assert xc.api_requests == []


async def test_list_alerts_parses_string_payload_and_sanitises(harness, xc):
    alerts = [{"labels": {"alertname": "WafAttackSpike", "severity": "critical"},
               "annotations": {"summary": "Spike" + TAGS, "description": "line1\nline2\x1b[31m"},
               "status": {"state": "active"}, "startsAt": "2026-10-31T00:00:00Z"}]
    xc.add("GET", NS + "/alerts", {"data": json.dumps(alerts)})
    data = result_json(await harness.call("list_alerts", {"namespace": "prod", "alertname": "WafAttackSpike",
                                                          "severity": "critical"}))
    alert = data["data"][0]
    assert alert["summary"] == "Spike" and "\n" not in alert["description"] and "\x1b" not in alert["description"]
    assert alert["state"] == "active" and alert["labels"]["severity"] == "critical"
    params = xc.api_requests[-1].url.params
    assert params["filter"] == '{alertname="WafAttackSpike", severity="critical"}' and "inactive" not in params


async def test_alert_filters_cannot_inject(harness, xc):
    for value in ['x", severity="info', "a\nb", "x}"]:
        assert (await harness.call("list_alerts", {"namespace": "prod", "alertname": value})).isError
    assert xc.api_requests == []


async def test_alerts_history(harness, xc):
    xc.add("GET", NS + "/alerts/history", {"alerts": [json.dumps({"labels": {"alertname": "A"}}), "not json"],
                                           "total_hits": "2"})
    data = result_json(await harness.call("query_alerts_history", {"namespace": "prod", "start": "6h",
                                                                   "severity": "major"}))
    assert data["data"][0]["labels"] == {"alertname": "A"} and data["data"][1] == {"unparsed": True}
    params = xc.api_requests[-1].url.params
    assert params["filter"] == '{severity="major"}' and params["start_time"] < params["end_time"]


async def test_service_policy_sets_are_readable(harness, xc):
    xc.add("GET", "/api/config/namespaces/prod/service_policy_sets", {"items": [{"name": "default"}]})
    data = result_json(await harness.call("list_objects", {"kind": "service_policy_set", "namespace": "prod"}))
    assert data["data"][0]["name"] == "default"


# --- console pages review: certificate expiry, new read-only kinds, shared namespace ----------
def _iso(days: int) -> str:
    from datetime import UTC, datetime, timedelta
    return (datetime.now(UTC) + timedelta(days=days, hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cert_routes(xc, certs: dict, lbs: dict | None = None, chains: dict | None = None):
    base = "/api/config/namespaces/prod"
    for kind, objects in (("certificates", certs), ("http_loadbalancers", lbs or {}),
                          ("certificate_chains", chains or {})):
        xc.add("GET", f"{base}/{kind}", {"items": [{"name": n} for n in objects]})
        for name, spec in objects.items():
            xc.add("GET", f"{base}/{kind}/{name}", spec if isinstance(spec, tuple) else {"spec": spec})


async def test_certificate_expiry_sorted_with_users_and_no_private_key(harness, xc):
    secret = "string:///LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t"
    _cert_routes(xc, certs={
        "shop-cert": {"private_key": {"clear_secret_info": {"url": secret}},
                      "infos": [{"common_name": "shop.example.com", "subject_alternative_names": ["shop.example.com",
                                 "www.shop.example.com" + TAGS], "issuer": "R11", "expiry": _iso(12)}],
                      "http_loadbalancers": [{"name": "shop", "namespace": "prod"}]},
        "old-cert": {"infos": [{"common_name": "old.example.com", "expiry": _iso(-3)}]},
        "weird": {"infos": [{"common_name": "w", "expiry": "not a date"}]},
    }, lbs={"api": {"auto_cert_info": {"auto_cert_expiry": _iso(60), "auto_cert_subject": "CN=api.example.com",
                                       "auto_cert_issuer": "Let's Encrypt", "auto_cert_state": "CertificateValid"}},
            "plain": {"domains": ["x"]}})
    result = await harness.call("list_certificate_expiry", {"namespace": "prod"})
    assert "LS0tLS1" not in result.content[0].text and "string:///" not in result.content[0].text
    data = result_json(result)
    rows = data["data"]
    assert [r["name"] for r in rows] == ["old-cert", "shop-cert", "api", "weird"]
    assert [r["days_left"] for r in rows[:3]] == [-3, 12, 60] and rows[3]["days_left"] is None
    assert rows[1]["used_by"] == ["http_loadbalancer/shop"]
    assert rows[1]["subject_alternative_names"] == ["shop.example.com", "www.shop.example.com"]
    assert rows[2]["source"] == "lb_auto_cert" and rows[2]["state"] == "CertificateValid"
    assert data["expired"] == 1 and data["unknown_expiry"] == 1 and data["incomplete"] is False


async def test_certificate_expiry_filter_chains_and_incomplete(harness, xc):
    _cert_routes(xc, certs={"soon": {"infos": [{"common_name": "a", "expiry": _iso(5)}]},
                            "later": {"infos": [{"common_name": "b", "expiry": _iso(200)}]},
                            "broken": ({}, )},
                 chains={"intermediate": {"infos": [{"common_name": "R11", "expiry": _iso(20)}]}})
    xc.add("GET", "/api/config/namespaces/prod/certificates/broken", (403, {}))
    data = result_json(await harness.call("list_certificate_expiry", {
        "namespace": "prod", "within_days": 30, "include_chains": True, "include_auto_certs": False}))
    assert [(r["source"], r["name"]) for r in data["data"]] == [("certificate", "soon"), ("chain", "intermediate")]
    assert data["incomplete"] is True


@pytest.mark.parametrize(("kind", "collection"), [
    ("certificate_chain", "certificate_chains"), ("cdn_cache_rule", "cdn_cache_rules"),
    ("bigip_virtual_server", "bigip_virtual_servers"), ("public_ip", "public_ips"),
])
async def test_console_pages_added_read_only(harness, xc, kind, collection):
    xc.add("GET", f"/api/config/namespaces/prod/{collection}", {"items": [{"name": "o1"}]})
    data = result_json(await harness.call("list_objects", {"kind": kind, "namespace": "prod"}))
    assert data["data"][0]["name"] == "o1"
    from f5xc_waap_mcp import catalog
    assert not catalog.kind(kind).writable


async def test_posture_explains_how_to_read_a_shared_waf(xc):
    from tests.conftest import Harness, make_settings
    harness = Harness(make_settings(allowed_namespaces=("prod",)), xc)
    xc.add("GET", "/api/config/namespaces/prod/http_loadbalancers/shop",
           {"spec": {"app_firewall": {"name": "corp-waf", "namespace": "shared"}}})
    data = result_json(await harness.call("get_lb_security_posture", {"namespace": "prod", "name": "shop"}))["data"]
    assert "'shared' not allow-listed" in data["waf_mode"] and "F5XC_ALLOWED_NAMESPACES" in data["waf_mode"]
    assert all("/shared/" not in r.url.path for r in xc.requests)
