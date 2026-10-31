"""Topics: tools and object kinds grouped by subject, each enabled individually.

``F5XC_MCP_TOPICS`` selects them (default ``all``):

  all                      every topic
  waf,posture              only these (plus ``core``)
  all,-dns,-bot_and_users  everything except these

A tool of a disabled topic is not registered, so it does not exist for the
model (smaller tool list, fewer tokens, smaller attack surface). The object
kinds of a disabled topic are refused by the generic tools (list_objects,
get_object, plan_create_object). ``core`` is always on. Write tools still need
F5XC_MCP_MODE=write and F5XC_MCP_ENABLE_WRITES=true: a topic never grants write.

Object kinds belong to the topic of their catalogue family (data/catalog.json);
tools are assigned below. tests/test_topics.py checks that every registered tool
has a topic.
"""

from __future__ import annotations

CORE = "core"

# topic -> one-line description (shown by list_supported_kinds)
TOPICS: dict[str, str] = {
    CORE: "tool and namespace discovery, generic object read (always on)",
    "load_balancing": "HTTP/TCP/CDN load balancers, origin pools, health checks, certificates, DNS info, performance",
    "waf": "App Firewall, WAF exclusions, signatures version, rule hits, false positive triage",
    "policies": "service policies, rate limiters, IP prefix sets, firewalls",
    "ddos": "L7 DDoS auto-mitigation rules",
    "bot_and_users": "bot defense, malicious users, app settings",
    "api_security": "API definitions, discovery, sensitive data",
    "network_security": "network firewalls, Fast ACLs",
    "dns": "DNS zones, DNS load balancers",
    "observability": "alerts, alert policies, log receivers",
    "events_logs": "security events, incidents, suspicious users, access and audit logs",
    "posture": "security posture of load balancers, namespace audit",
}

# Tools that are not tied to a subject but to the write mode: registered only when
# at least one write tool is registered.
WRITES = "@writes"

TOOL_TOPICS: dict[str, str] = {
    # core
    "list_supported_kinds": CORE, "list_namespaces": CORE, "list_objects": CORE, "get_object": CORE,
    "plan_create_object": CORE,
    # load balancing
    "get_lb_dns_info": "load_balancing", "get_lb_performance": "load_balancing",
    "list_certificate_expiry": "load_balancing",
    # waf
    "get_waf_signatures_version": "waf", "get_waf_rule_hits": "waf", "suggest_waf_exclusion_rule": "waf",
    "plan_set_lb_waf": "waf", "plan_set_waf_mode": "waf", "plan_add_waf_exclusion_rule": "waf",
    # policies
    "get_active_service_policies": "policies", "plan_update_ip_prefix_set": "policies",
    # ddos
    "get_lb_dos_mitigation_rules": "ddos",
    # observability
    "list_alerts": "observability", "query_alerts_history": "observability",
    # events and logs
    "query_security_events": "events_logs", "aggregate_security_events": "events_logs",
    "query_security_incidents": "events_logs", "query_suspicious_users": "events_logs",
    "query_access_logs": "events_logs", "aggregate_access_logs": "events_logs", "query_audit_logs": "events_logs",
    # posture
    "get_lb_security_posture": "posture", "audit_namespace_security": "posture",
    # write mode
    "apply_plan": WRITES, "plan_revert": WRITES,
}


def resolve_topics(spec: tuple[str, ...] | list[str]) -> frozenset[str]:
    """Enabled topics for a TOPICS setting. ``core`` is always included; unknown names raise."""
    items = [s.strip().lower() for s in spec if s.strip()] or ["all"]
    adds: set[str] = set()
    removes: set[str] = set()
    use_all = False
    for item in items:
        name = item.removeprefix("-")
        if name != "all" and name not in TOPICS:
            raise ValueError(f"unknown topic {name!r}; known: all, {', '.join(sorted(TOPICS))}")
        if item.startswith("-"):
            removes.add(name)
        elif name == "all":
            use_all = True
        else:
            adds.add(name)
    if "all" in removes:
        raise ValueError("'-all' is not allowed: list the topics to enable instead")
    enabled = (set(TOPICS) if use_all else adds) - removes
    enabled.add(CORE)
    return frozenset(enabled)
