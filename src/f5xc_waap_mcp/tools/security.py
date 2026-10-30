"""WAAP read tools: security posture of load balancers, security events,
incidents, suspicious users, access and audit logs, WAF exclusion suggestions,
DoS auto-mitigation rules."""

import asyncio
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field, StringConstraints

from .. import catalog, sanitize
from ..errors import Code, SecureError
from ..runtime import Runtime, ToolClass
from .common import (
    AccessLogMatcher,
    AuditLogMatcher,
    EventMatcher,
    Namespace,
    ObjectName,
    TimeSpec,
    build_query,
    time_window,
)

# Aggregation keys, copied from the enums of the API reference
# (schemaapp_securityKeyField, logaccess_logKeyField).
SecurityEventKey = Literal[
    "CITY", "COUNTRY", "SEC_EVENT_TYPE", "SRC_SITE", "VH_NAME", "VH_TYPE", "USER", "VIOLATION", "ATTACK_TYPE",
    "SIGNATURE", "THREAT_CAMPAIGN", "URI", "BOT_CLASSIFICATION", "AUTOMATION_TYPE", "DOMAIN", "BOT_TYPE",
    "BOT_NAME", "SRC_IP", "TLS_FINGERPRINT", "ASN", "API_EP", "BROWSER_TYPE", "DEVICE_TYPE", "METHOD",
    "RESP_CODE", "RESP_CODE_DETAILS", "SEC_EVENT_NAME", "WAF_MODE", "SIGNATURE_NAME", "SIGNATURE_ID",
    "SIGNATURE_STATE", "SIGNATURE_ACCURACY", "VIOLATION_STATE", "THREAT_CAMPAIGN_NAME", "THREAT_CAMPAIGN_ID",
    "VIOLATION_RATING", "SERVICE_POLICY", "SERVICE_POLICY_RESULT", "SIGNATURE_CONTEXT", "ACTION", "NAMESPACE",
    "REQ_RISK", "REQ_RISK_REASON", "JA4_TLS_FINGERPRINT", "MALWARE_NAME", "MALWARE_TYPE", "THREAT_LEVEL",
]
AccessLogKey = Literal[
    "API_ENDPOINT", "APP_TYPE", "AUTHORITY", "ASN", "BROWSER_TYPE", "CITY", "COUNTRY", "DEVICE_TYPE", "DST",
    "DST_INSTANCE", "DST_SITE", "METHOD", "SCHEME", "REMOTE_LOCATION", "REQ_PATH", "RSP_CODE", "RSP_CODE_CLASS",
    "RSP_CODE_DETAILS", "SRC", "SRC_INSTANCE", "SRC_IP", "SRC_SITE", "TLS_CIPHER_SUITE", "TLS_FINGERPRINT",
    "TLS_VERSION", "USER", "VH_NAME", "VH_TYPE", "VISITOR_ID", "JA4_TLS_FINGERPRINT",
]
DetectionContext = Literal[
    "CONTEXT_ANY", "CONTEXT_BODY", "CONTEXT_REQUEST", "CONTEXT_RESPONSE", "CONTEXT_PARAMETER",
    "CONTEXT_HEADER", "CONTEXT_COOKIE", "CONTEXT_URL", "CONTEXT_URI",
]
AUDIT_LOG_FIELDS = (
    "time", "@timestamp", "req_id", "user", "method", "req_path", "rsp_code", "rsp_code_details", "src_ip",
    "namespace", "authority",
)
INCIDENT_FIELDS = (*sanitize.EVENT_FIELDS, "incident_id", "id", "start_time", "end_time", "count", "type", "name")

Limit = Annotated[int, Field(ge=1, le=500, description="Maximum number of records (capped by the server).")]
TopK = Annotated[int, Field(ge=1, le=50, description="Number of top values returned.")]

# --- security posture -----------------------------------------------------------
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _choice(choices: dict[str, Any], group: str) -> str | None:
    value = choices.get(group)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("choice")
    return None


def assess_http_lb(summary: dict[str, Any], spec: dict[str, Any], waf_mode: str | None) -> list[dict[str, str]]:
    """Heuristic findings for one HTTP load balancer. Pure function (unit tested)."""
    c = summary["choices"]
    findings: list[dict[str, str]] = []

    def add(severity: str, check: str, detail: str) -> None:
        findings.append({"severity": severity, "check": check, "detail": detail})

    if _choice(c, "waf_choice") == "disable_waf":
        add("high", "waf_disabled", "No App Firewall attached to the load balancer.")
    elif waf_mode == "monitoring":
        add("high", "waf_monitoring_only", "The attached App Firewall is in monitoring mode: attacks are not blocked.")
    if _choice(c, "loadbalancer_type") == "http":
        add("medium", "no_tls", "Plain HTTP listener (no TLS).")
    if _choice(c, "ip_reputation_choice") == "disable_ip_reputation":
        add("medium", "ip_reputation_disabled", "IP reputation filtering is disabled.")
    if _choice(c, "bot_defense_choice") == "disable_bot_defense":
        add("low", "bot_defense_disabled", "Bot defense is disabled.")
    if _choice(c, "malicious_user_detection_choice") == "disable_malicious_user_detection":
        add("low", "malicious_user_detection_disabled", "Malicious user detection is disabled.")
    if _choice(c, "rate_limit_choice") == "disable_rate_limit":
        add("low", "rate_limit_disabled", "No rate limiting.")
    if _choice(c, "service_policy_choice") == "no_service_policies":
        add("low", "no_service_policies", "No service policy is applied.")
    if _choice(c, "api_discovery_choice") == "disable_api_discovery":
        add("low", "api_discovery_disabled", "API discovery is disabled.")
    if _choice(c, "client_side_defense_choice") == "disable_client_side_defense":
        add("info", "client_side_defense_disabled", "Client-side defense is disabled.")
    if _choice(c, "threat_mesh_choice") == "disable_threat_mesh":
        add("info", "threat_mesh_disabled", "Threat mesh is disabled.")
    trusted = spec.get("trusted_clients")
    if isinstance(trusted, list) and trusted:
        add("info", "trusted_clients", f"{len(trusted)} trusted client rule(s) can skip security processing.")
    exclusion = spec.get("waf_exclusion") if isinstance(spec.get("waf_exclusion"), dict) else {}
    inline = exclusion.get("waf_exclusion_inline_rules") if isinstance(exclusion, dict) else None
    rules = inline.get("rules") if isinstance(inline, dict) else None
    if isinstance(rules, list):
        skipping = [r for r in rules if isinstance(r, dict) and "waf_skip_processing" in r]
        if skipping:
            add("medium", "waf_skip_rules", f"{len(skipping)} WAF exclusion rule(s) skip all WAF processing.")
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])


def register(mcp: FastMCP, rt: Runtime) -> None:
    lb_kind = catalog.kind("http_loadbalancer")
    fw_kind = catalog.kind("app_firewall")

    async def waf_mode(ref: dict[str, str] | None, namespace: str, cache: dict[str, str | None]) -> str | None:
        if ref is None:
            return None
        ns = ref.get("namespace") or namespace
        key = f"{ns}/{ref['name']}"
        if key not in cache:
            if not rt.settings.namespace_allowed(ns):
                cache[key] = "unknown (namespace not allow-listed)"
            else:
                fw = await rt.xc("GET", catalog.kind_path(fw_kind, "get", namespace=ns, name=ref["name"]))
                spec = fw.get("spec", {}) if isinstance(fw, dict) else {}
                cache[key] = "blocking" if "blocking" in spec else "monitoring" if "monitoring" in spec else None
        return cache[key]

    async def posture(namespace: str, name: str, cache: dict[str, str | None]) -> dict[str, Any]:
        obj = await rt.xc("GET", catalog.kind_path(lb_kind, "get", namespace=namespace, name=name))
        if not isinstance(obj, dict):
            raise SecureError(Code.RESPONSE_INVALID)
        summary = sanitize.summarize(lb_kind, obj)
        spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
        waf = summary["choices"].get("waf_choice")
        mode = await waf_mode(waf.get("ref") if isinstance(waf, dict) else None, namespace, cache)
        return {
            "name": summary["name"],
            "domains": summary.get("domains", []),
            "waf_mode": mode,
            "controls": {
                group: summary["choices"].get(group) for group in (
                    "loadbalancer_type", "waf_choice", "bot_defense_choice", "api_discovery_choice",
                    "api_definition_choice", "ip_reputation_choice", "malicious_user_detection_choice",
                    "rate_limit_choice", "service_policy_choice", "challenge_type",
                    "l7_ddos_auto_mitigation_action", "slow_ddos_mitigation_choice", "threat_mesh_choice",
                    "client_side_defense_choice", "sensitive_data_policy_choice", "malware_protection",
                    "advertise_choice",
                )
            },
            "findings": assess_http_lb(summary, spec, mode),
        }

    @rt.tool(mcp, ToolClass.READ, title="Security posture of an HTTP load balancer")
    async def get_lb_security_posture(namespace: Namespace, name: ObjectName, ctx: Context) -> dict:
        """Which WAAP protections are enabled on one HTTP load balancer (WAF and its blocking/monitoring
        mode, bot defense, API discovery, IP reputation, malicious users, rate limit, service policies,
        DDoS, TLS...) with heuristic findings sorted by severity."""
        rt.require_namespace(namespace)
        data = await posture(namespace, name, {})
        return sanitize.envelope("get_lb_security_posture", data, namespace=namespace, heuristic=True)

    @rt.tool(mcp, ToolClass.READ, title="Audit the HTTP load balancers of a namespace")
    async def audit_namespace_security(namespace: Namespace, ctx: Context) -> dict:
        """Security posture of every HTTP load balancer of a namespace (max 50), with a count of
        findings by severity. Good starting point for a WAAP review."""
        rt.require_namespace(namespace)
        listing = await rt.xc("GET", catalog.kind_path(lb_kind, "list", namespace=namespace))
        names = [i["name"] for i in listing.get("items", []) if isinstance(i, dict) and isinstance(i.get("name"), str)]
        cache: dict[str, str | None] = {}
        semaphore = asyncio.Semaphore(4)

        async def one(lb_name: str) -> dict[str, Any]:
            async with semaphore:
                try:
                    return await posture(namespace, lb_name, cache)
                except SecureError as exc:
                    return {"name": sanitize.text(lb_name, 63), "error": str(exc.code)}

        results = await asyncio.gather(*(one(n) for n in names[:50]))
        totals = {s: 0 for s in SEVERITY_ORDER}
        for result in results:
            for finding in result.get("findings", []):
                totals[finding["severity"]] += 1
        return sanitize.envelope("audit_namespace_security", list(results), namespace=namespace,
                                 load_balancers=len(names), truncated=len(names) > 50, findings=totals,
                                 heuristic=True)

    # --- security events ----------------------------------------------------------
    async def log_query(endpoint: str, namespace: str, start: str, end: str | None, matchers: list | None,
                        limit: int, newest_first: bool) -> dict[str, Any]:
        start_s, end_s = time_window(rt.settings, start, end)
        method, path = catalog.data_path(endpoint, namespace=namespace)
        body = {
            "namespace": namespace, "query": build_query(matchers), "start_time": start_s, "end_time": end_s,
            "limit": min(limit, rt.settings.max_events), "sort": "DESCENDING" if newest_first else "ASCENDING",
            "scroll": False,
        }
        payload = await rt.xc(method, path, body=body)
        if not isinstance(payload, dict):
            raise SecureError(Code.RESPONSE_INVALID)
        payload["_window"] = {"start": start_s, "end": end_s}
        return payload

    @rt.tool(mcp, ToolClass.READ, title="Query security events")
    async def query_security_events(
        namespace: Namespace,
        ctx: Context,
        start: TimeSpec = "1h",
        end: TimeSpec | None = None,
        filters: Annotated[list[EventMatcher] | None, Field(max_length=10)] = None,
        limit: Limit = 50,
        newest_first: bool = True,
    ) -> dict:
        """WAF / bot / API / service-policy security events of a namespace (newest first by default).
        Filters example: [{"field": "vh_name", "value": "ves-io-http-loadbalancer-shop"},
        {"field": "country", "op": "!=", "value": "FR"}]. Each event keeps documented fields only
        (time, source, request, action, signatures, violations, bot info...)."""
        rt.require_namespace(namespace)
        payload = await log_query("security_events.query", namespace, start, end, filters, limit, newest_first)
        events = payload.get("events") if isinstance(payload.get("events"), list) else []
        data = [sanitize.project_record(e, sanitize.EVENT_FIELDS) for e in events]
        return sanitize.envelope("query_security_events", data, namespace=namespace, window=payload["_window"],
                                 total_hits=sanitize.text(payload.get("total_hits"), 20), returned=len(data))

    @rt.tool(mcp, ToolClass.READ, title="Top values of security events")
    async def aggregate_security_events(
        namespace: Namespace,
        group_by: SecurityEventKey,
        ctx: Context,
        start: TimeSpec = "24h",
        end: TimeSpec | None = None,
        filters: Annotated[list[EventMatcher] | None, Field(max_length=10)] = None,
        top_k: TopK = 10,
    ) -> dict:
        """Count security events by a field (e.g. SIGNATURE_ID, SRC_IP, VH_NAME, ATTACK_TYPE, COUNTRY,
        BOT_NAME, ACTION). Use it to find the top attackers, the noisiest signatures (false positive
        candidates) or the most targeted load balancers."""
        rt.require_namespace(namespace)
        start_s, end_s = time_window(rt.settings, start, end)
        method, path = catalog.data_path("security_events.aggregate", namespace=namespace)
        body = {"namespace": namespace, "query": build_query(filters), "start_time": start_s, "end_time": end_s,
                "aggs": {"top": {"field_aggregation": {"field": group_by, "topk": top_k}}}}
        payload = await rt.xc(method, path, body=body)
        return sanitize.envelope("aggregate_security_events", _buckets(payload), namespace=namespace,
                                 group_by=group_by, window={"start": start_s, "end": end_s},
                                 total_hits=sanitize.text(payload.get("total_hits") if isinstance(payload, dict)
                                                          else None, 20))

    @rt.tool(mcp, ToolClass.READ, title="Query security incidents")
    async def query_security_incidents(
        namespace: Namespace,
        ctx: Context,
        start: TimeSpec = "24h",
        end: TimeSpec | None = None,
        filters: Annotated[list[EventMatcher] | None, Field(max_length=10)] = None,
        limit: Limit = 50,
    ) -> dict:
        """Security incidents (groups of related security events) of a namespace."""
        rt.require_namespace(namespace)
        payload = await log_query("security_incidents.query", namespace, start, end, filters, limit, True)
        incidents = payload.get("incidents") if isinstance(payload.get("incidents"), list) else []
        data = [sanitize.project_record(i, INCIDENT_FIELDS) for i in incidents]
        return sanitize.envelope("query_security_incidents", data, namespace=namespace,
                                 window=payload["_window"], returned=len(data))

    @rt.tool(mcp, ToolClass.READ, title="Query suspicious user logs")
    async def query_suspicious_users(
        namespace: Namespace,
        ctx: Context,
        start: TimeSpec = "24h",
        end: TimeSpec | None = None,
        limit: Limit = 50,
    ) -> dict:
        """Suspicious / malicious user logs (malicious user detection) of a namespace."""
        rt.require_namespace(namespace)
        payload = await log_query("suspicious_users.query", namespace, start, end, None, limit, True)
        logs = payload.get("logs") if isinstance(payload.get("logs"), list) else []
        data = [sanitize.project_record(item, sanitize.EVENT_FIELDS) for item in logs]
        return sanitize.envelope("query_suspicious_users", data, namespace=namespace,
                                 window=payload["_window"], returned=len(data))

    @rt.tool(mcp, ToolClass.READ, title="Query access logs")
    async def query_access_logs(
        namespace: Namespace,
        ctx: Context,
        start: TimeSpec = "15m",
        end: TimeSpec | None = None,
        filters: Annotated[list[AccessLogMatcher] | None, Field(max_length=10)] = None,
        limit: Limit = 50,
    ) -> dict:
        """HTTP access logs of a namespace (request, response code, source, latency). Filter with e.g.
        [{"field": "vh_name", "value": "..."}, {"field": "rsp_code", "op": "=~", "value": "5.*"}]."""
        rt.require_namespace(namespace)
        payload = await log_query("access_logs.query", namespace, start, end, filters, limit, True)
        logs = payload.get("logs") if isinstance(payload.get("logs"), list) else []
        data = [sanitize.project_record(item, sanitize.ACCESS_LOG_FIELDS) for item in logs]
        return sanitize.envelope("query_access_logs", data, namespace=namespace, window=payload["_window"],
                                 total_hits=sanitize.text(payload.get("total_hits"), 20), returned=len(data))

    @rt.tool(mcp, ToolClass.READ, title="Top values of access logs")
    async def aggregate_access_logs(
        namespace: Namespace,
        group_by: AccessLogKey,
        ctx: Context,
        start: TimeSpec = "1h",
        end: TimeSpec | None = None,
        filters: Annotated[list[AccessLogMatcher] | None, Field(max_length=10)] = None,
        top_k: TopK = 10,
    ) -> dict:
        """Count access log entries by a field (e.g. RSP_CODE, REQ_PATH, SRC_IP, COUNTRY, AUTHORITY)."""
        rt.require_namespace(namespace)
        start_s, end_s = time_window(rt.settings, start, end)
        method, path = catalog.data_path("access_logs.aggregate", namespace=namespace)
        body = {"namespace": namespace, "query": build_query(filters), "start_time": start_s, "end_time": end_s,
                "aggs": {"top": {"field_aggregation": {"field": group_by, "topk": top_k}}}}
        payload = await rt.xc(method, path, body=body)
        return sanitize.envelope("aggregate_access_logs", _buckets(payload), namespace=namespace,
                                 group_by=group_by, window={"start": start_s, "end": end_s})

    @rt.tool(mcp, ToolClass.READ, title="Query configuration audit logs")
    async def query_audit_logs(
        namespace: Namespace,
        ctx: Context,
        start: TimeSpec = "24h",
        end: TimeSpec | None = None,
        filters: Annotated[list[AuditLogMatcher] | None, Field(max_length=10)] = None,
        limit: Limit = 50,
    ) -> dict:
        """Who changed what in the namespace (F5 XC audit logs: user, method, path, response code).
        Request bodies are never returned."""
        rt.require_namespace(namespace)
        payload = await log_query("audit_logs.query", namespace, start, end, filters, limit, True)
        logs = payload.get("logs") if isinstance(payload.get("logs"), list) else []
        data = [sanitize.project_record(item, AUDIT_LOG_FIELDS) for item in logs]
        return sanitize.envelope("query_audit_logs", data, namespace=namespace, window=payload["_window"],
                                 returned=len(data))

    # --- load balancer helpers ----------------------------------------------------
    @rt.tool(mcp, ToolClass.READ, title="Suggest a WAF exclusion rule")
    async def suggest_waf_exclusion_rule(
        namespace: Namespace,
        name: Annotated[str, StringConstraints(min_length=1, max_length=63, pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
                        Field(description="HTTP load balancer name.")],
        domain: Annotated[str, StringConstraints(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.\-*]+$")],
        ctx: Context,
        req_path: Annotated[str | None, StringConstraints(max_length=256, pattern=r"^/[^\s\"{}\\]*$")] = None,
        signature_ids: Annotated[list[Annotated[int, Field(ge=0, le=299999999)]] | None, Field(max_length=20)] = None,
        violations: Annotated[
            list[Annotated[str, StringConstraints(pattern=r"^VIOL_[A-Z0-9_]{2,60}$")]] | None, Field(max_length=20)
        ] = None,
        context: DetectionContext = "CONTEXT_ANY",
        context_name: Annotated[str | None, StringConstraints(max_length=128, pattern=r"^[A-Za-z0-9_.\-]+$")] = None,
    ) -> dict:
        """Ask F5 XC to compute a WAF exclusion rule for a false positive (signature ids and/or
        violations seen in security events). Nothing is changed: the suggestion can then be applied
        with plan_add_waf_exclusion_rule (when writes are enabled)."""
        rt.require_namespace(namespace)
        if not signature_ids and not violations:
            raise SecureError(Code.INVALID_ARGUMENT, "Give signature_ids and/or violations.")
        for sig in signature_ids or []:
            if sig != 0 and not 200000001 <= sig <= 299999999:
                raise SecureError(Code.INVALID_ARGUMENT, "Signature ids are 0 or 200000001-299999999.")
        ctx_fields: dict[str, Any] = {"context": context}
        if context_name:
            ctx_fields["context_name"] = context_name
        body: dict[str, Any] = {
            "namespace": namespace, "name": name, "domain": domain,
            "exclude_signature_contexts": [{"signature_id": s, **ctx_fields} for s in signature_ids or []],
            "exclude_violation_contexts": [{"exclude_violation": v, **ctx_fields} for v in violations or []],
        }
        if req_path:
            body["req_path"] = req_path
        method, path = catalog.data_path("waf_exclusion.suggest", namespace=namespace, name=name)
        payload = await rt.xc(method, path, body=body)
        payload = payload if isinstance(payload, dict) else {}
        data = {
            "waf_exclusion_rule": sanitize.redact(payload.get("waf_exclusion_rule") or {}),
            "waf_exclusion_policy": sanitize.ref(payload.get("waf_exclusion_policy")),
            "found_existing_rule": "found_existing_rule" in payload,
        }
        return sanitize.envelope("suggest_waf_exclusion_rule", data, namespace=namespace, load_balancer=name)

    @rt.tool(mcp, ToolClass.READ, title="DoS auto-mitigation rules of a load balancer")
    async def get_lb_dos_mitigation_rules(namespace: Namespace, name: ObjectName, ctx: Context) -> dict:
        """L7 DDoS auto-mitigation rules currently active on an HTTP load balancer."""
        rt.require_namespace(namespace)
        method, path = catalog.data_path("http_loadbalancer.dos_automitigation_rules", namespace=namespace,
                                         name=name)
        payload = await rt.xc(method, path)
        rules = payload.get("dos_automitigation_rules", []) if isinstance(payload, dict) else []
        data = [sanitize.redact(r) for r in rules[:100] if isinstance(r, dict)]
        return sanitize.envelope("get_lb_dos_mitigation_rules", data, namespace=namespace, load_balancer=name)

    @rt.tool(mcp, ToolClass.READ, title="DNS information of a load balancer")
    async def get_lb_dns_info(namespace: Namespace, name: ObjectName, ctx: Context) -> dict:
        """DNS information of an HTTP load balancer (host name / CNAME to configure, VIPs)."""
        rt.require_namespace(namespace)
        method, path = catalog.data_path("http_loadbalancer.dns_info", namespace=namespace, name=name)
        payload = await rt.xc(method, path)
        return sanitize.envelope("get_lb_dns_info", sanitize.redact(payload), namespace=namespace,
                                 load_balancer=name)

    @rt.tool(mcp, ToolClass.READ, title="Latest WAF signatures version")
    async def get_waf_signatures_version(ctx: Context) -> dict:
        """Latest attack signatures version published by F5 for the XC WAF."""
        method, path = catalog.data_path("waf.latest_signatures_version")
        payload = await rt.xc(method, path)
        version = payload.get("version") if isinstance(payload, dict) else None
        return sanitize.envelope("get_waf_signatures_version", {"version": sanitize.text(version, 60)})


def _buckets(payload: Any) -> list[dict[str, Any]]:
    aggs = payload.get("aggs") if isinstance(payload, dict) else None
    top = aggs.get("top") if isinstance(aggs, dict) else None
    field = top.get("field_aggregation") if isinstance(top, dict) else None
    buckets = field.get("buckets") if isinstance(field, dict) else None
    if not isinstance(buckets, list):
        return []
    return [
        {"key": sanitize.text(b.get("key"), 200), "count": sanitize.text(b.get("count"), 20)}
        for b in buckets[:50] if isinstance(b, dict)
    ]
