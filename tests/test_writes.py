import re

import httpx
import pytest
from mcp import types

from f5xc_waap_mcp.errors import SecureError
from f5xc_waap_mcp.plans import PlanStore, diff
from tests.conftest import FakeXC, Harness, error_text, make_settings, result_json

LB = "/api/config/namespaces/prod/http_loadbalancers/shop"
FW = "/api/config/namespaces/prod/app_firewalls/fw1"
IPS = "/api/config/namespaces/prod/ip_prefix_sets/blocklist"


def replace_form(spec):
    return {"replace_form": {"metadata": {"name": "x", "namespace": "prod", "labels": {"a": "b"}}, "spec": spec},
            "spec": spec}


class Human:
    """Elicitation callback that records the prompt and answers like a careful human."""

    def __init__(self, name, *, action="accept", approve=True, hash_prefix=None):
        self.name, self.action, self.approve, self.hash_prefix = name, action, approve, hash_prefix
        self.messages: list[str] = []
        self.schemas: list[dict] = []

    async def __call__(self, context, params):
        self.messages.append(params.message)
        self.schemas.append(params.requestedSchema)
        if self.action != "accept":
            return types.ElicitResult(action=self.action)
        content = {"approve": self.approve, "object_name": self.name}
        if "hash_prefix" in params.requestedSchema["properties"]:
            digest = re.search(r"Body SHA-256: ([0-9a-f]{64})", params.message).group(1)
            content["hash_prefix"] = self.hash_prefix if self.hash_prefix is not None else digest[:8]
        return types.ElicitResult(action="accept", content=content)


async def plan_then_apply(harness, plan_tool, args, human):
    async with harness.session(elicitation_callback=human) as session:
        plan = result_json(await session.call_tool(plan_tool, args))["data"]
        applied = await session.call_tool("apply_plan", {"plan_id": plan["plan_id"]})
    return plan, applied


def puts(xc):
    return [r for r in xc.api_requests if r.method in ("PUT", "POST")]


# --- confirmation content (item 1) ----------------------------------------------
async def test_confirmation_shows_complete_diff_and_hash(write_harness, xc):
    xc.add("GET", FW, replace_form({"monitoring": {}, "default_detection_settings": {}}))
    xc.add("PUT", FW, {})
    human = Human("fw1")
    plan, applied = await plan_then_apply(
        write_harness, "plan_set_waf_mode", {"namespace": "prod", "name": "fw1", "mode": "blocking"}, human)
    assert not applied.isError, applied.content
    message = human.messages[0]
    assert plan["body_sha256"] in message
    assert plan["diff_text"] in message
    assert "+ spec.blocking = {}" in message and "- spec.monitoring (was {})" in message
    assert "HIGH RISK" not in message and plan["risk"] == "standard"
    assert puts(xc)[0].url.path == FW


@pytest.mark.parametrize(("tool", "args", "route", "spec", "reason"), [
    ("plan_set_waf_mode", {"namespace": "prod", "name": "fw1", "mode": "monitoring"}, FW,
     {"blocking": {}}, "switched to monitoring"),
    ("plan_set_lb_waf", {"namespace": "prod", "name": "shop"}, LB,
     {"app_firewall": {"name": "fw1", "namespace": "prod"}}, "WAF disabled"),
    ("plan_update_ip_prefix_set", {"namespace": "prod", "name": "blocklist", "add": ["203.0.113.7/32"]}, IPS,
     {"ipv4_prefixes": []}, "allow-list"),
])
async def test_high_risk_banner_and_hash_challenge(write_harness, xc, tool, args, route, spec, reason):
    xc.add("GET", route, replace_form(spec))
    xc.add("PUT", route, {})
    human = Human(args["name"])
    plan, applied = await plan_then_apply(write_harness, tool, args, human)
    assert plan["risk"] == "HIGH" and any(reason in r for r in plan["risks"])
    assert human.messages[0].startswith("!!! HIGH RISK !!!")
    assert "hash_prefix" in human.schemas[0]["properties"]
    assert not applied.isError, applied.content


async def test_high_risk_with_wrong_hash_is_not_applied(write_harness, xc):
    xc.add("GET", FW, replace_form({"blocking": {}}))
    xc.add("PUT", FW, {})
    _, applied = await plan_then_apply(write_harness, "plan_set_waf_mode",
                                       {"namespace": "prod", "name": "fw1", "mode": "monitoring"},
                                       Human("fw1", hash_prefix="00000000"))
    assert "mismatch" in error_text(applied)
    assert puts(xc) == []


async def test_monitoring_waf_attached_is_high_risk(write_harness, xc):
    xc.add("GET", LB, replace_form({"disable_waf": {}}))
    xc.add("GET", FW, {"spec": {"monitoring": {}}})
    plan = result_json(await write_harness.call("plan_set_lb_waf", {"namespace": "prod", "name": "shop",
                                                                    "app_firewall": "fw1"}))["data"]
    assert plan["risk"] == "HIGH" and "monitoring mode" in plan["risks"][0]


@pytest.mark.parametrize("human", [Human("fw1", action="decline"), Human("fw1", action="cancel"),
                                   Human("fw1", approve=False), Human("other")])
async def test_refused_confirmation_applies_nothing(write_harness, xc, human):
    xc.add("GET", FW, replace_form({"monitoring": {}}))
    xc.add("PUT", FW, {})
    _, applied = await plan_then_apply(write_harness, "plan_set_waf_mode",
                                       {"namespace": "prod", "name": "fw1", "mode": "blocking"}, human)
    assert "confirmation_required" in error_text(applied)
    assert puts(xc) == []


async def test_client_without_elicitation_cannot_apply(write_harness, xc):
    xc.add("GET", FW, replace_form({"monitoring": {}}))
    _, applied = await plan_then_apply(write_harness, "plan_set_waf_mode",
                                       {"namespace": "prod", "name": "fw1", "mode": "blocking"}, None)
    assert "unsupported_client" in error_text(applied)
    assert puts(xc) == []


# --- exhaustive diff (item 2) -----------------------------------------------------
def test_deep_change_in_named_rules_is_visible_and_reorder_reported():
    rule = lambda name, action: {"metadata": {"name": name}, "spec": {"action": action, "ip": "10.0.0.0/8"}}  # noqa: E731
    before = {"rule_list": {"rules": [rule("a", "DENY"), rule("b", "DENY")]}}
    after = {"rule_list": {"rules": [rule("b", "DENY"), rule("a", "ALLOW")]}}
    ops = diff(before, after)
    assert {"op": "change", "path": "spec.rule_list.rules[a].spec.action", "before": '"DENY"',
            "after": '"ALLOW"'} in ops
    assert any(op["op"] == "reorder" for op in ops)


def test_large_values_and_large_diffs_are_refused_not_truncated():
    with pytest.raises(SecureError) as exc:
        diff({}, {"description": "x" * 400})
    assert str(exc.value.code) == "diff_too_large"
    with pytest.raises(SecureError):
        diff({}, {"items": [{"v": i} for i in range(200)]})


def test_secret_fields_are_refused():
    with pytest.raises(SecureError) as exc:
        diff({}, {"tls": {"private_key": {"clear_secret_info": {"url": "string:///x"}}}})
    assert str(exc.value.code) == "secret_field_refused"


def test_control_characters_cannot_forge_diff_lines():
    ops = diff({}, {"labels": {"a\n+ spec.fake = 1": "x\n- injected"}})
    rendered = "\n".join(f"{op['path']} {op['after']}" for op in ops)
    assert "\n" not in rendered


# --- narrowed scope (item 3) ------------------------------------------------------
async def test_generic_replace_no_longer_exists(write_harness):
    async with write_harness.session() as session:
        names = {t.name for t in (await session.list_tools()).tools}
    assert "plan_replace_object" not in names


async def test_create_limited_to_inert_kinds(write_harness, xc):
    for kind in ("http_loadbalancer", "origin_pool", "certificate"):
        result = await write_harness.call("plan_create_object", {"kind": kind, "namespace": "prod", "name": "n",
                                                                 "spec": {}})
        assert result.isError
    assert xc.api_requests == []


async def test_create_object(write_harness, xc):
    path = "/api/config/namespaces/prod/ip_prefix_sets"
    xc.add("POST", path, {})
    plan, applied = await plan_then_apply(write_harness, "plan_create_object", {
        "kind": "ip_prefix_set", "namespace": "prod", "name": "new-set",
        "spec": {"ipv4_prefixes": [{"ipv4_prefix": "203.0.113.0/24"}]}, "labels": {"owner": "secops"}},
        Human("new-set"))
    assert not applied.isError
    assert plan["diff_text"] == '+ spec.ipv4_prefixes[0].ipv4_prefix = "203.0.113.0/24"'
    assert xc.bodies(path)[0]["metadata"] == {"labels": {"owner": "secops"}, "name": "new-set", "namespace": "prod"}


async def test_create_checks_fields_against_reference(write_harness, xc):
    result = await write_harness.call("plan_create_object", {"kind": "app_firewall", "namespace": "prod",
                                                             "name": "n", "spec": {"evil": 1}})
    assert "Unknown spec fields" in error_text(result)


# --- audit of applied changes (item 4) ---------------------------------------------
async def test_plan_and_apply_are_audited_with_plan_id(write_harness, xc):
    xc.add("GET", FW, replace_form({"monitoring": {}}))
    xc.add("PUT", FW, {})
    plan, _ = await plan_then_apply(write_harness, "plan_set_waf_mode",
                                    {"namespace": "prod", "name": "fw1", "mode": "blocking"}, Human("fw1"))
    events = {line["event"]: line for line in write_harness.audit() if line["event"] != "tool_call"}
    calls = [line for line in write_harness.audit() if line["event"] == "tool_call"]
    for event in ("plan_created", "plan_confirmation", "plan_applied"):
        assert events[event]["plan_id"] == plan["plan_id"]
        assert events[event]["user"] == "alice@example.com"
    assert events["plan_created"]["body_sha256"] == events["plan_applied"]["body_sha256"] == plan["body_sha256"]
    assert events["plan_confirmation"]["outcome"] == "approved"
    assert events["plan_applied"]["status"] == "ok"
    apply_line = calls[-1]
    assert apply_line["tool"] == "apply_plan" and apply_line["plan_id"] == plan["plan_id"]
    assert (apply_line["kind"], apply_line["namespace"], apply_line["target"]) == ("app_firewall", "prod", "fw1")
    assert calls[0]["plan_id"] == plan["plan_id"]


async def test_declined_confirmation_is_audited(write_harness, xc):
    xc.add("GET", FW, replace_form({"monitoring": {}}))
    await plan_then_apply(write_harness, "plan_set_waf_mode",
                          {"namespace": "prod", "name": "fw1", "mode": "blocking"}, Human("fw1", action="decline"))
    outcomes = [line["outcome"] for line in write_harness.audit() if line["event"] == "plan_confirmation"]
    assert outcomes == ["declined"]
    assert not [line for line in write_harness.audit() if line["event"] == "plan_applied"]


# --- other safeguards ------------------------------------------------------------
async def test_stale_plan_is_refused(write_harness, xc):
    states = iter([{"monitoring": {}}, {"monitoring": {}, "allow_all_response_codes": {}}])
    xc.add("GET", FW, lambda request: httpx.Response(200, json=replace_form(next(states))))
    _, applied = await plan_then_apply(write_harness, "plan_set_waf_mode",
                                       {"namespace": "prod", "name": "fw1", "mode": "blocking"}, Human("fw1"))
    assert "plan_stale" in error_text(applied)
    assert puts(xc) == []
    applied_events = [line for line in write_harness.audit() if line["event"] == "plan_applied"]
    assert applied_events[0]["status"] == "error" and applied_events[0]["error_code"] == "plan_stale"


async def test_plan_is_single_use(write_harness, xc):
    xc.add("GET", FW, replace_form({"monitoring": {}}))
    xc.add("PUT", FW, {})
    async with write_harness.session(elicitation_callback=Human("fw1")) as session:
        plan = result_json(await session.call_tool(
            "plan_set_waf_mode", {"namespace": "prod", "name": "fw1", "mode": "blocking"}))["data"]
        assert not (await session.call_tool("apply_plan", {"plan_id": plan["plan_id"]})).isError
        again = await session.call_tool("apply_plan", {"plan_id": plan["plan_id"]})
    assert "plan_unknown" in error_text(again)


def test_plan_bound_to_identity():
    store = PlanStore(300)
    plan = store.create(identity="user:alice", operation="replace", kind="app_firewall", namespace="prod",
                        name="fw1", method="PUT", path="/p", body={}, base_version="h", summary="s", diff=[])
    with pytest.raises(SecureError):
        store.take(plan.plan_id, "user:mallory")


async def test_protected_namespace_is_never_written(write_harness, xc):
    result = await write_harness.call("plan_set_waf_mode", {"namespace": "shared", "name": "fw1",
                                                            "mode": "blocking"})
    assert "namespace_protected" in error_text(result)
    assert xc.api_requests == []


async def test_waf_from_namespace_outside_allowlist_refused(write_harness, xc):
    xc.add("GET", LB, replace_form({"disable_waf": {}}))
    result = await write_harness.call("plan_set_lb_waf", {"namespace": "prod", "name": "shop",
                                                          "app_firewall": "fw1", "app_firewall_namespace": "other"})
    assert "namespace_forbidden" in error_text(result)


@pytest.mark.parametrize("prefix", ["0.0.0.0/0", "10.0.0.0/8", "203.0.113.7/24", "not-an-ip"])
async def test_ip_prefixes_must_be_specific_and_exact(write_harness, xc, prefix):
    result = await write_harness.call("plan_update_ip_prefix_set", {"namespace": "prod", "name": "blocklist",
                                                                    "add": [prefix]})
    assert "invalid_argument" in error_text(result)
    assert xc.api_requests == []


async def test_minimum_prefix_is_configurable(xc):
    harness = Harness(make_settings(mode="write", enable_writes=True, min_ipv4_prefix_len=8), xc)
    xc.add("GET", IPS, replace_form({"ipv4_prefixes": []}))
    assert not (await harness.call("plan_update_ip_prefix_set", {"namespace": "prod", "name": "blocklist",
                                                                 "add": ["10.0.0.0/8"]})).isError


async def test_ip_prefix_set_update(write_harness, xc):
    xc.add("GET", IPS, replace_form({"ipv4_prefixes": [{"ipv4_prefix": "198.51.100.0/24"}]}))
    xc.add("PUT", IPS, {})
    _, applied = await plan_then_apply(write_harness, "plan_update_ip_prefix_set", {
        "namespace": "prod", "name": "blocklist", "add": ["203.0.113.7"], "remove": ["198.51.100.0/24"],
        "comment": "incident 42"}, Human("blocklist"))
    assert not applied.isError
    assert xc.bodies(IPS)[0]["spec"]["ipv4_prefixes"] == [{"ipv4_prefix": "203.0.113.7/32",
                                                          "description": "incident 42"}]


async def test_waf_exclusion_rule(write_harness, xc):
    xc.add("GET", LB, replace_form({"domains": ["a.example"]}))
    rule = {"metadata": {"name": "fp-search"}, "exact_value": "a.example", "path_prefix": "/search",
            "app_firewall_detection_control": {"exclude_signature_contexts": [
                {"signature_id": 200001234, "context": "CONTEXT_PARAMETER", "context_name": "q"}]}}
    plan = result_json(await write_harness.call("plan_add_waf_exclusion_rule", {
        "namespace": "prod", "name": "shop", "rule": rule}))["data"]
    assert "spec.waf_exclusion.waf_exclusion_inline_rules.rules[fp-search].path_prefix" in plan["diff_text"]
    assert plan["risk"] == "standard"
    all_sigs = {**rule, "metadata": {"name": "fp-all"}, "app_firewall_detection_control": {
        "exclude_signature_contexts": [{"signature_id": 0, "context": "CONTEXT_ANY"}]}}
    plan = result_json(await write_harness.call("plan_add_waf_exclusion_rule", {
        "namespace": "prod", "name": "shop", "rule": all_sigs}))["data"]
    assert plan["risk"] == "HIGH"
    skip = {k: v for k, v in rule.items() if k != "app_firewall_detection_control"} | {"waf_skip_processing": {}}
    assert (await write_harness.call("plan_add_waf_exclusion_rule", {
        "namespace": "prod", "name": "shop", "rule": skip})).isError


async def test_read_mode_harness_has_no_write_path():
    harness = Harness(make_settings(), FakeXC())
    assert "apply_plan" not in harness.runtime.registered
