from f5xc_waap_mcp.runtime import ToolClass
from tests.conftest import FakeXC, Harness, make_settings

WRITE_TOOLS = {
    "plan_set_lb_waf", "plan_set_waf_mode", "plan_update_ip_prefix_set", "plan_add_waf_exclusion_rule",
    "plan_replace_object", "plan_create_object", "apply_plan",
}


async def test_read_mode_publishes_no_write_tool():
    harness = Harness(make_settings(), FakeXC())
    async with harness.session() as session:
        tools = {t.name: t for t in (await session.list_tools()).tools}
    assert not WRITE_TOOLS & set(tools)
    assert all(t.annotations.readOnlyHint for t in tools.values())
    assert set(harness.runtime.registered.values()) == {ToolClass.READ}


async def test_flag_without_write_mode_publishes_nothing_more():
    harness = Harness(make_settings(enable_writes=True), FakeXC())
    assert not WRITE_TOOLS & set(harness.runtime.registered)


async def test_write_mode_publishes_plan_and_apply():
    harness = Harness(make_settings(mode="write", enable_writes=True), FakeXC())
    async with harness.session() as session:
        names = {t.name for t in (await session.list_tools()).tools}
    assert names >= WRITE_TOOLS


async def test_no_generic_or_destructive_tool_exists():
    harness = Harness(make_settings(mode="write", enable_writes=True), FakeXC())
    for name in harness.runtime.registered:
        assert "delete" not in name and "raw" not in name and "request" not in name


async def test_no_bypass_parameter_in_schemas():
    harness = Harness(make_settings(mode="write", enable_writes=True), FakeXC())
    async with harness.session() as session:
        for tool in (await session.list_tools()).tools:
            props = set(tool.inputSchema.get("properties", {}))
            assert not props & {"dry_run", "dryRun", "force", "confirm", "url", "path", "method"}, tool.name
