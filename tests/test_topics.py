"""Topics: tools and object kinds enabled by subject (F5XC_MCP_TOPICS)."""

import pytest
from pydantic import ValidationError

from f5xc_waap_mcp import catalog
from f5xc_waap_mcp.topics import CORE, TOOL_TOPICS, TOPICS, WRITES, resolve_topics
from tests.conftest import FakeXC, Harness, error_text, make_settings, result_json


def names(harness: Harness) -> set[str]:
    return set(harness.runtime.registered)


def full_write_harness(**kw) -> Harness:
    return Harness(make_settings(mode="write", enable_writes=True, **kw), FakeXC())


def test_every_registered_tool_has_a_topic_and_every_topic_is_used():
    registered = names(full_write_harness())
    assert registered <= set(TOOL_TOPICS)
    assert set(TOOL_TOPICS) == registered  # no stale entry either
    assert {t for t in TOOL_TOPICS.values() if t != WRITES} <= set(TOPICS)
    used = {t for t in TOOL_TOPICS.values()} | {k.family for k in catalog.KINDS.values()}
    assert set(TOPICS) - {CORE} <= used  # no topic without tools or kinds
    assert {k.family for k in catalog.KINDS.values()} <= set(TOPICS)  # every kind family is a topic


@pytest.mark.parametrize(("spec", "expected"), [
    (("all",), set(TOPICS)),
    ((), set(TOPICS)),
    (("waf", "posture"), {"waf", "posture", CORE}),
    (("WAF ", " Posture"), {"waf", "posture", CORE}),
    (("all", "-dns", "-events_logs"), set(TOPICS) - {"dns", "events_logs"}),
    (("-dns", "all"), set(TOPICS) - {"dns"}),
    (("waf", "-waf"), {CORE}),
    (("-dns",), {CORE}),  # an exclusion alone leaves nothing enabled but core
])
def test_resolve_topics(spec, expected):
    assert resolve_topics(spec) == frozenset(expected)


@pytest.mark.parametrize("spec", [("foo",), ("waf", "-nope"), ("-all",)])
def test_resolve_topics_rejects_bad_input(spec):
    with pytest.raises(ValueError):
        resolve_topics(spec)


def test_core_can_never_be_disabled():
    assert CORE in resolve_topics(("all", "-core"))


def test_settings_parse_env_and_reject_unknown(monkeypatch):
    from f5xc_waap_mcp.config import Settings
    monkeypatch.setenv("F5XC_TENANT", "acme")
    monkeypatch.setenv("F5XC_ALLOWED_NAMESPACES", "prod")
    monkeypatch.setenv("F5XC_API_TOKEN", "RealPersonalTokenValue-000000")
    monkeypatch.setenv("F5XC_MCP_TOPICS", "waf, posture")
    assert Settings().enabled_topics == frozenset({"waf", "posture", CORE})
    monkeypatch.setenv("F5XC_MCP_TOPICS", "waf,bogus")
    with pytest.raises(ValidationError, match="unknown topic"):
        Settings()


def test_default_enables_every_topic_and_every_read_tool():
    from f5xc_waap_mcp.runtime import ToolClass
    harness = Harness(make_settings(), FakeXC())
    assert harness.runtime.settings.enabled_topics == frozenset(TOPICS)
    all_tools = full_write_harness().runtime.registered
    assert names(harness) == {n for n, c in all_tools.items() if c is ToolClass.READ}


def test_disabling_a_topic_removes_its_tools_and_only_its_tools():
    harness = Harness(make_settings(topics=("all", "-events_logs", "-posture")), FakeXC())
    registered = names(harness)
    assert not {n for n, t in TOOL_TOPICS.items() if t in ("events_logs", "posture")} & registered
    assert {"list_objects", "get_waf_rule_hits", "list_alerts"} <= registered


def test_allowlist_registers_only_the_chosen_subjects_plus_core():
    registered = names(Harness(make_settings(topics=("waf",)), FakeXC()))
    assert registered == {n for n, t in TOOL_TOPICS.items() if t in ("waf", CORE)
                          and n not in {"plan_set_lb_waf", "plan_set_waf_mode", "plan_add_waf_exclusion_rule",
                                        "plan_create_object"}}


def test_write_tools_of_a_disabled_topic_are_not_registered_in_write_mode():
    registered = names(full_write_harness(topics=("all", "-waf", "-policies")))
    assert not {"plan_set_waf_mode", "plan_set_lb_waf", "plan_add_waf_exclusion_rule",
                "plan_update_ip_prefix_set"} & registered
    assert {"plan_create_object", "apply_plan", "plan_revert"} <= registered


def test_a_topic_never_grants_write():
    registered = names(Harness(make_settings(topics=("waf",)), FakeXC()))  # read mode
    assert not {n for n in registered if n.startswith("plan_") or n == "apply_plan"}


def test_apply_and_revert_exist_only_with_a_write_tool():
    registered = names(Harness(make_settings(mode="write", enable_writes=True, topics=("posture",)), FakeXC()))
    assert "plan_create_object" in registered  # core write tool
    assert {"apply_plan", "plan_revert"} <= registered
    read_only = names(Harness(make_settings(topics=("posture",)), FakeXC()))
    assert not {"apply_plan", "plan_revert", "plan_create_object"} & read_only


async def test_disabled_tools_are_absent_from_tools_list():
    harness = Harness(make_settings(topics=("waf",)), FakeXC())
    async with harness.session() as session:
        listed = {t.name for t in (await session.list_tools()).tools}
    assert listed == names(harness) and "query_security_events" not in listed


async def test_generic_tools_refuse_kinds_of_disabled_topics():
    xc = FakeXC()
    harness = Harness(make_settings(topics=("waf",)), xc)
    xc.add("GET", "/api/config/namespaces/prod/app_firewalls", {"items": [{"name": "fw"}]})
    assert result_json(await harness.call("list_objects", {"kind": "app_firewall", "namespace": "prod"}))
    for tool, args in (("list_objects", {"kind": "dns_zone", "namespace": "prod"}),
                       ("get_object", {"kind": "http_loadbalancer", "namespace": "prod", "name": "shop"})):
        assert "topic_disabled" in error_text(await harness.call(tool, args))
    assert [r.url.path for r in xc.api_requests] == ["/api/config/namespaces/prod/app_firewalls"]


async def test_create_object_refuses_a_disabled_subject(xc):
    harness = Harness(make_settings(mode="write", enable_writes=True, topics=("waf",)), xc)
    result = await harness.call("plan_create_object", {"kind": "ip_prefix_set", "namespace": "prod", "name": "n",
                                                       "spec": {"ipv4_prefixes": []}})
    assert "topic_disabled" in error_text(result)
    assert xc.api_requests == []


async def test_list_supported_kinds_shows_only_enabled_subjects(xc):
    harness = Harness(make_settings(topics=("waf", "dns")), xc)
    data = result_json(await harness.call("list_supported_kinds"))
    assert set(data["data"]) == {"waf", "dns"}
    assert set(data["enabled_topics"]) == {"waf", "dns", CORE}
    assert "policies" in data["disabled_topics"] and "waf" not in data["disabled_topics"]
