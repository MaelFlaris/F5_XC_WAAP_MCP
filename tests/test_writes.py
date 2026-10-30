import pytest
from mcp import types

from f5xc_waap_mcp.errors import SecureError
from f5xc_waap_mcp.plans import PlanStore
from tests.conftest import error_text, result_json

LB = "/api/config/namespaces/prod/http_loadbalancers/shop"
FW = "/api/config/namespaces/prod/app_firewalls/fw1"
IPS = "/api/config/namespaces/prod/ip_prefix_sets/blocklist"


def replace_form(spec):
    return {"replace_form": {"metadata": {"name": "x", "namespace": "prod", "labels": {"a": "b"}}, "spec": spec},
            "spec": spec}


def approve(name):
    async def callback(context, params):
        assert name in params.message
        return types.ElicitResult(action="accept", content={"approve": True, "object_name": name})
    return callback


async def decline(context, params):
    return types.ElicitResult(action="decline")


async def plan_then_apply(harness, plan_tool, args, callback):
    async with harness.session(elicitation_callback=callback) as session:
        plan = result_json(await session.call_tool(plan_tool, args))["data"]
        applied = await session.call_tool("apply_plan", {"plan_id": plan["plan_id"]})
    return plan, applied


async def test_set_waf_mode_full_flow(write_harness, xc):
    xc.add("GET", FW, replace_form({"monitoring": {}, "default_detection_settings": {}}))
    xc.add("PUT", FW, {})
    plan, applied = await plan_then_apply(
        write_harness, "plan_set_waf_mode", {"namespace": "prod", "name": "fw1", "mode": "blocking"},
        approve("fw1"))
    assert {"op": "add", "path": "spec.blocking", "value": "{}"} in plan["diff"]
    assert {"op": "remove", "path": "spec.monitoring"} in plan["diff"]
    assert not applied.isError, applied.content
    body = xc.bodies(FW)[0]
    assert body["spec"] == {"blocking": {}, "default_detection_settings": {}}
    assert body["metadata"] == {"name": "fw1", "namespace": "prod", "labels": {"a": "b"}}


async def test_declined_confirmation_applies_nothing(write_harness, xc):
    xc.add("GET", FW, replace_form({"monitoring": {}}))
    xc.add("PUT", FW, {})
    _, applied = await plan_then_apply(
        write_harness, "plan_set_waf_mode", {"namespace": "prod", "name": "fw1", "mode": "blocking"}, decline)
    assert "confirmation_required" in error_text(applied)
    assert not [r for r in xc.requests if r.method == "PUT"]


async def test_wrong_typed_name_applies_nothing(write_harness, xc):
    xc.add("GET", FW, replace_form({"monitoring": {}}))
    _, applied = await plan_then_apply(
        write_harness, "plan_set_waf_mode", {"namespace": "prod", "name": "fw1", "mode": "blocking"},
        approve("other"))
    assert applied.isError
    assert not [r for r in xc.requests if r.method == "PUT"]


async def test_client_without_elicitation_cannot_apply(write_harness, xc):
    xc.add("GET", FW, replace_form({"monitoring": {}}))
    _plan, applied = await plan_then_apply(
        write_harness, "plan_set_waf_mode", {"namespace": "prod", "name": "fw1", "mode": "blocking"}, None)
    assert "elicitation" in error_text(applied)
    assert not [r for r in xc.requests if r.method == "PUT"]


async def test_stale_plan_is_refused(write_harness, xc):
    states = iter([{"monitoring": {}}, {"monitoring": {}, "allow_all_response_codes": {}}])
    xc.add("GET", FW, lambda request: __import__("httpx").Response(200, json=replace_form(next(states))))
    _, applied = await plan_then_apply(
        write_harness, "plan_set_waf_mode", {"namespace": "prod", "name": "fw1", "mode": "blocking"},
        approve("fw1"))
    assert "plan_stale" in error_text(applied)
    assert not [r for r in xc.requests if r.method == "PUT"]


async def test_plan_is_single_use(write_harness, xc):
    xc.add("GET", FW, replace_form({"monitoring": {}}))
    xc.add("PUT", FW, {})
    async with write_harness.session(elicitation_callback=approve("fw1")) as session:
        plan = result_json(await session.call_tool(
            "plan_set_waf_mode", {"namespace": "prod", "name": "fw1", "mode": "blocking"}))["data"]
        assert not (await session.call_tool("apply_plan", {"plan_id": plan["plan_id"]})).isError
        again = await session.call_tool("apply_plan", {"plan_id": plan["plan_id"]})
    assert "plan_unknown" in error_text(again)


def test_plan_bound_to_identity():
    store = PlanStore(300)
    plan = store.create(identity="alice", operation="replace", kind="app_firewall", namespace="prod",
                        name="fw1", body={}, base_version="h", summary="s")
    with pytest.raises(SecureError):
        store.take(plan.plan_id, "mallory")


async def test_protected_namespace_is_never_written(write_harness, xc):
    result = await write_harness.call("plan_set_waf_mode", {"namespace": "shared", "name": "fw1",
                                                            "mode": "blocking"})
    assert "namespace_protected" in error_text(result)
    assert xc.requests == []


async def test_lb_waf_attach(write_harness, xc):
    xc.add("GET", LB, replace_form({"domains": ["a.example"], "disable_waf": {}}))
    plan = result_json(await write_harness.call("plan_set_lb_waf", {"namespace": "prod", "name": "shop",
                                                                    "app_firewall": "fw1"}))["data"]
    paths = {d["path"] for d in plan["diff"]}
    assert paths == {"spec.app_firewall", "spec.disable_waf"}


async def test_ip_prefix_set_update(write_harness, xc):
    xc.add("GET", IPS, replace_form({"ipv4_prefixes": [{"ipv4_prefix": "198.51.100.0/24"}]}))
    xc.add("PUT", IPS, {})
    _plan, applied = await plan_then_apply(write_harness, "plan_update_ip_prefix_set", {
        "namespace": "prod", "name": "blocklist", "add": ["203.0.113.7"], "remove": ["198.51.100.0/24"],
        "comment": "incident 42"}, approve("blocklist"))
    assert not applied.isError
    assert xc.bodies(IPS)[0]["spec"]["ipv4_prefixes"] == [{"ipv4_prefix": "203.0.113.7/32",
                                                          "description": "incident 42"}]
    bad = await write_harness.call("plan_update_ip_prefix_set", {"namespace": "prod", "name": "blocklist",
                                                                 "add": ["not-an-ip"]})
    assert bad.isError


async def test_waf_exclusion_rule(write_harness, xc):
    xc.add("GET", LB, replace_form({"domains": ["a.example"]}))
    rule = {"metadata": {"name": "fp-search"}, "exact_value": "a.example", "path_prefix": "/search",
            "app_firewall_detection_control": {"exclude_signature_contexts": [
                {"signature_id": 200001234, "context": "CONTEXT_PARAMETER", "context_name": "q"}]}}
    plan = result_json(await write_harness.call("plan_add_waf_exclusion_rule", {
        "namespace": "prod", "name": "shop", "rule": rule}))["data"]
    assert plan["diff"][0]["path"] == "spec.waf_exclusion"
    skip = {**rule, "waf_skip_processing": {}}
    skip.pop("app_firewall_detection_control")
    assert (await write_harness.call("plan_add_waf_exclusion_rule", {
        "namespace": "prod", "name": "shop", "rule": skip})).isError


async def test_generic_replace_checks_fields_against_reference(write_harness, xc):
    xc.add("GET", "/api/config/namespaces/prod/origin_pools/p1", replace_form({"port": 80}))
    bad = await write_harness.call("plan_replace_object", {"kind": "origin_pool", "namespace": "prod",
                                                           "name": "p1", "spec": {"port": 443, "evil": 1}})
    assert "Unknown spec fields" in error_text(bad)
    ok = await write_harness.call("plan_replace_object", {"kind": "origin_pool", "namespace": "prod",
                                                          "name": "p1", "spec": {"port": 443}})
    assert not ok.isError


async def test_read_only_kinds_cannot_be_written(write_harness, xc):
    result = await write_harness.call("plan_replace_object", {"kind": "certificate", "namespace": "prod",
                                                              "name": "c", "spec": {}})
    assert result.isError  # not in the writable enum
    assert xc.requests == []


async def test_create_object(write_harness, xc):
    path = "/api/config/namespaces/prod/ip_prefix_sets"
    xc.add("POST", path, {})
    _plan, applied = await plan_then_apply(write_harness, "plan_create_object", {
        "kind": "ip_prefix_set", "namespace": "prod", "name": "new-set",
        "spec": {"ipv4_prefixes": [{"ipv4_prefix": "203.0.113.0/24"}]}, "labels": {"owner": "secops"}},
        approve("new-set"))
    assert not applied.isError
    assert xc.bodies(path)[0]["metadata"] == {"name": "new-set", "namespace": "prod", "labels": {"owner": "secops"}}
