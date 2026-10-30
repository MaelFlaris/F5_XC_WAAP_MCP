"""Generate src/f5xc_waap_mcp/data/catalog.json from the official F5 XC API docs.

Every page under https://docs.cloud.f5.com/docs-v2/api/<slug> embeds the
OpenAPI (swagger 2) document of the object in its ``__NEXT_DATA__`` payload.
This script extracts, for each object kind the server supports:

  * the List / Get / Create / Replace paths (operationId ``...API.<Op>``);
  * the top-level "oneof" groups of the object spec (``x-ves-oneof-field-*``),
    used to summarise a configuration without inventing field names;
  * the names of the spec properties.

It also checks that every data endpoint the server calls (security events,
logs, suggestions...) exists in the published specs. Nothing is guessed: if a
path is missing from the docs, generation fails.

Usage:
    python scripts/generate_catalog.py [--cache DIR]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.request

DOCS = "https://docs.cloud.f5.com/docs-v2/api"
OUT = pathlib.Path(__file__).resolve().parents[1] / "src" / "f5xc_waap_mcp" / "data" / "catalog.json"

# kind id -> (doc slug, family, writable, sensitive)
# writable : the kind may be modified through plan/apply when writes are enabled.
# sensitive: the spec may contain secrets; only the summary view is offered.
KINDS: dict[str, tuple[str, str, bool, bool]] = {
    # Load balancing
    "http_loadbalancer": ("views-http-loadbalancer", "load_balancing", True, False),
    "tcp_loadbalancer": ("views-tcp-loadbalancer", "load_balancing", True, False),
    "cdn_loadbalancer": ("views-cdn-loadbalancer", "load_balancing", True, False),
    "origin_pool": ("views-origin-pool", "load_balancing", True, False),
    "healthcheck": ("healthcheck", "load_balancing", True, False),
    "certificate": ("certificate", "load_balancing", False, True),
    "trusted_ca_list": ("trusted-ca-list", "load_balancing", False, False),
    # Web application firewall
    "app_firewall": ("app-firewall", "waf", True, False),
    "waf_exclusion_policy": ("waf-exclusion-policy", "waf", True, False),
    # Policies
    "service_policy": ("service-policy", "policies", True, False),
    "service_policy_rule": ("service-policy-rule", "policies", False, False),
    "rate_limiter_policy": ("views-rate-limiter-policy", "policies", True, False),
    "rate_limiter": ("rate-limiter", "policies", True, False),
    "ip_prefix_set": ("ip-prefix-set", "policies", True, False),
    "forward_proxy_policy": ("views-forward-proxy-policy", "policies", False, False),
    "protocol_policer": ("protocol-policer", "policies", False, False),
    "policer": ("policer", "policies", False, False),
    # Bot defense / malicious users
    "bot_defense_app_infrastructure": ("views-bot-defense-app-infrastructure", "bot_and_users", False, False),
    "malicious_user_mitigation": ("malicious-user-mitigation", "bot_and_users", True, False),
    "user_identification": ("user-identification", "bot_and_users", True, False),
    "app_setting": ("app-setting", "bot_and_users", True, False),
    "app_type": ("app-type", "bot_and_users", True, False),
    # API security
    "api_definition": ("views-api-definition", "api_security", True, False),
    "app_api_group": ("views-app-api-group", "api_security", True, False),
    "api_discovery": ("api-sec-api-discovery", "api_security", True, False),
    "api_crawler": ("api-sec-api-crawler", "api_security", False, True),
    "api_testing": ("api-sec-api-testing", "api_security", False, True),
    "sensitive_data_policy": ("sensitive-data-policy", "api_security", True, False),
    "data_type": ("data-type", "api_security", False, False),
    # Network security (read only)
    "network_firewall": ("network-firewall", "network_security", False, False),
    "enhanced_firewall_policy": ("enhanced-firewall-policy", "network_security", False, False),
    "fast_acl": ("fast-acl", "network_security", False, False),
    # DNS (read only)
    "dns_zone": ("dns-zone", "dns", False, False),
    "dns_load_balancer": ("dns-load-balancer", "dns", False, False),
    "dns_lb_pool": ("dns-lb-pool", "dns", False, False),
    "dns_lb_health_check": ("dns-lb-health-check", "dns", False, False),
    "geo_location_set": ("geo-location-set", "dns", False, False),
    # Observability (read only, receivers can hold secrets)
    "alert_policy": ("alert-policy", "observability", False, False),
    "alert_receiver": ("alert-receiver", "observability", False, True),
    "global_log_receiver": ("global-log-receiver", "observability", False, True),
}

# Data / custom endpoints called by the server: id -> (doc slug, method, path)
DATA_ENDPOINTS: dict[str, tuple[str, str, str]] = {
    "namespace.list": ("namespace", "get", "/api/web/namespaces"),
    "namespace.active_service_policies": (
        "namespace", "get", "/api/config/namespaces/{namespace}/active_service_policies"),
    "security_events.query": ("app-security", "post", "/api/data/namespaces/{namespace}/app_security/events"),
    "security_events.aggregate": (
        "app-security", "post", "/api/data/namespaces/{namespace}/app_security/events/aggregation"),
    "security_incidents.query": ("app-security", "post", "/api/data/namespaces/{namespace}/app_security/incidents"),
    "suspicious_users.query": (
        "app-security", "post", "/api/data/namespaces/{namespace}/app_security/suspicious_user_logs"),
    "waf_exclusion.suggest": (
        "app-security", "post",
        "/api/config/namespaces/{namespace}/http_loadbalancers/{name}/waf_exclusion/suggestion"),
    "access_logs.query": ("log", "post", "/api/data/namespaces/{namespace}/access_logs"),
    "access_logs.aggregate": ("log", "post", "/api/data/namespaces/{namespace}/access_logs/aggregation"),
    "audit_logs.query": ("log", "post", "/api/data/namespaces/{namespace}/audit_logs"),
    "http_loadbalancer.dos_automitigation_rules": (
        "views-http-loadbalancer", "get",
        "/api/config/namespaces/{namespace}/http_loadbalancers/{name}/dos_automitigation_rules"),
    "http_loadbalancer.dns_info": (
        "views-http-loadbalancer", "get", "/api/config/namespaces/{namespace}/http_loadbalancers/{name}/get-dns-info"),
    "waf.latest_signatures_version": ("waf-signatures-changelog", "get", "/api/waf/latest-signatures-version"),
}

NEXT_DATA = re.compile(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', re.S)


def fetch(slug: str, cache: pathlib.Path | None) -> str:
    if cache is not None:
        cached = cache / f"{slug}.html"
        if cached.exists():
            return cached.read_text(encoding="utf-8")
    with urllib.request.urlopen(f"{DOCS}/{slug}", timeout=60) as resp:
        html = resp.read().decode("utf-8")
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        (cache / f"{slug}.html").write_text(html, encoding="utf-8")
    return html


def find_spec(node: object) -> dict | None:
    if isinstance(node, dict):
        if isinstance(node.get("paths"), dict) and ("swagger" in node or "openapi" in node):
            return node
        for value in node.values():
            found = find_spec(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = find_spec(value)
            if found is not None:
                return found
    elif isinstance(node, str) and node.lstrip().startswith("{") and '"paths"' in node[:20000]:
        try:
            return find_spec(json.loads(node))
        except ValueError:
            return None
    return None


def load_spec(slug: str, cache: pathlib.Path | None) -> dict:
    match = NEXT_DATA.search(fetch(slug, cache))
    if match is None:
        raise SystemExit(f"{slug}: no __NEXT_DATA__ payload")
    spec = find_spec(json.loads(match.group(1)))
    if spec is None:
        raise SystemExit(f"{slug}: no OpenAPI document found")
    return spec


def crud_paths(spec: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for path, ops in spec["paths"].items():
        for op in ops.values():
            if not isinstance(op, dict):
                continue
            parts = op.get("operationId", "").split(".")
            if len(parts) >= 2 and parts[-2] == "API" and parts[-1] in {"List", "Get", "Create", "Replace"}:
                out.setdefault(parts[-1].lower(), path)
    return out


def spec_definition(spec: dict, get_path: str) -> dict:
    defs = spec["definitions"]
    response = spec["paths"][get_path]["get"]["responses"]["200"]["schema"]["$ref"].split("/")[-1]
    ref = defs[response]["properties"]["spec"]["$ref"].split("/")[-1]
    return defs[ref]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", type=pathlib.Path, default=None, help="directory caching the doc pages")
    args = parser.parse_args()

    specs: dict[str, dict] = {}
    kinds: dict[str, dict] = {}
    for kind, (slug, family, writable, sensitive) in KINDS.items():
        spec = specs.setdefault(slug, load_spec(slug, args.cache))
        paths = crud_paths(spec)
        missing = {"list", "get"} - set(paths)
        if missing:
            raise SystemExit(f"{kind}: missing {missing} in {slug}")
        definition = spec_definition(spec, paths["get"])
        oneofs = {
            key[len("x-ves-oneof-field-"):]: json.loads(value)
            for key, value in sorted(definition.items())
            if key.startswith("x-ves-oneof-field-")
        }
        kinds[kind] = {
            "doc": f"{DOCS}/{slug}",
            "family": family,
            "writable": writable and "create" in paths and "replace" in paths,
            "sensitive": sensitive,
            "paths": {op: paths[op] for op in ("list", "get", "create", "replace") if op in paths},
            "oneofs": oneofs,
            "spec_fields": sorted(definition.get("properties", {})),
        }

    data: dict[str, dict] = {}
    for endpoint_id, (slug, method, path) in DATA_ENDPOINTS.items():
        spec = specs.setdefault(slug, load_spec(slug, args.cache))
        if method not in spec["paths"].get(path, {}):
            raise SystemExit(f"{endpoint_id}: {method.upper()} {path} not found in {slug}")
        op = spec["paths"][path][method]
        data[endpoint_id] = {
            "doc": f"{DOCS}/{slug}",
            "method": method.upper(),
            "path": path,
            "operation": op.get("operationId", ""),
        }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"source": DOCS, "kinds": kinds, "data": data}, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(f"wrote {OUT} ({len(kinds)} kinds, {len(data)} data endpoints)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
