import pytest

from f5xc_waap_mcp import catalog
from f5xc_waap_mcp.errors import SecureError


def test_every_kind_has_list_and_get_and_doc():
    assert len(catalog.KINDS) >= 40
    for k in catalog.KINDS.values():
        assert {"list", "get"} <= set(k.paths), k.name
        assert k.doc.startswith("https://docs.cloud.f5.com/docs-v2/api/")
        if k.writable:
            assert {"create", "replace"} <= set(k.paths), k.name


def test_paths_come_from_the_official_reference():
    assert catalog.kind_path(catalog.kind("app_firewall"), "list", namespace="prod") == \
        "/api/config/namespaces/prod/app_firewalls"
    assert catalog.kind_path(catalog.kind("dns_zone"), "list", namespace="prod") == \
        "/api/config/dns/namespaces/prod/dns_zones"
    assert catalog.kind_path(catalog.kind("service_policy"), "get", namespace="prod", name="p1") == \
        "/api/config/namespaces/prod/service_policys/p1"
    assert catalog.kind_path(catalog.kind("http_loadbalancer"), "replace", namespace="prod", name="lb") == \
        "/api/config/namespaces/prod/http_loadbalancers/lb"


@pytest.mark.parametrize("bad", ["../system", "a/b", "x?y=1", "UPPER", "-a", "a-", "", "a" * 64, "a%2F", "a b"])
def test_path_segments_are_validated(bad):
    with pytest.raises(SecureError):
        catalog.kind_path(catalog.kind("origin_pool"), "get", namespace="prod", name=bad)


def test_no_delete_operation_in_catalogue():
    for k in catalog.KINDS.values():
        assert "delete" not in k.paths


def test_sensitive_kinds_are_never_writable():
    for k in catalog.KINDS.values():
        if k.sensitive:
            assert not k.writable, k.name


def test_waap_oneofs_present():
    lb = catalog.kind("http_loadbalancer")
    assert lb.oneofs["waf_choice"] == ["app_firewall", "disable_waf"]
    assert catalog.kind("app_firewall").oneofs["enforcement_mode_choice"] == ["blocking", "monitoring"]


def test_writable_flag_matches_what_the_write_tools_modify():
    """The catalogue's writable flag must equal the kinds the plan tools touch (no dormant
    write permission on kinds no tool needs)."""
    import inspect
    import re

    from f5xc_waap_mcp.tools import changes

    source = inspect.getsource(changes)
    targeted = set(re.findall(r'writable\("([a-z_]+)"', source))
    used = targeted | set(changes.CREATABLE_KINDS)
    assert {name for name, k in catalog.KINDS.items() if k.writable} == used
    assert targeted == {"http_loadbalancer", "app_firewall", "ip_prefix_set"}
