"""WAAP read tools: security posture of load balancers, security events,
incidents, suspicious users, access and audit logs, WAF exclusion suggestions,
DoS auto-mitigation rules."""

import asyncio
import json
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .. import catalog, sanitize
from ..errors import Code, SecureError
from ..runtime import Runtime, ToolClass
from .common import (
    AccessLogMatcher,
    AuditLogMatcher,
    EventMatcher,
    Matcher,
    Namespace,
    ObjectName,
    TimeSpec,
    build_query,
    parse_time,
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
# wafMetricLabel enum of the WAF metrics API (docs-v2/api/waf).
WafMetricLabel = Literal[
    "NAMESPACE", "APP_TYPE", "VIRTUAL_HOST", "SITE", "SERVICE", "INSTANCE", "WAF_INSTANCE_ID", "RULE_ID",
    "RULE_SEVERITY", "RULE_TAG", "WAF_MODE", "BOT_TYPE", "BOT_NAME",
]
# Subset of schemagraphMetricType (docs-v2/api/graph-service) relevant to a load balancer.
PerfMetric = Literal[
    "HTTP_REQUEST_RATE", "HTTP_ERROR_RATE", "HTTP_ERROR_RATE_4XX", "HTTP_ERROR_RATE_5XX", "HTTP_RESPONSE_LATENCY",
    "HTTP_RESPONSE_LATENCY_PERCENTILE_50", "HTTP_RESPONSE_LATENCY_PERCENTILE_90",
    "HTTP_RESPONSE_LATENCY_PERCENTILE_99", "HTTP_APP_LATENCY", "HTTP_SERVER_DATA_TRANSFER_TIME", "CLIENT_RTT",
    "SERVER_RTT", "REQUEST_THROUGHPUT", "RESPONSE_THROUGHPUT", "ACTIVE_CONNECTIONS", "NEW_CONNECTION_RATE",
    "TCP_ERROR_RATE", "PEAK_REQUEST_RATE", "PEAK_LATENCY",
]
AlertValue = Annotated[str | None, StringConstraints(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:\- ]+$")]


class WafLabelFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: WafMetricLabel
    op: Literal["EQ", "NEQ"] = "EQ"
    value: Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f]+$")]


class AlertMatcher(Matcher):
    field: Literal["alertname", "severity"]

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
                # Typically a WAF in "shared": reading it only needs that namespace in the
                # allow-list (writes to shared stay refused regardless).
                cache[key] = (f"unknown (namespace {sanitize.text(ns, 63)!r} not allow-listed: add it to "
                              "F5XC_ALLOWED_NAMESPACES for read access)")
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

    # --- WAF rule hits (false positive triage) ---------------------------------------
    @rt.tool(mcp, ToolClass.READ, title="WAF rule hits")
    async def get_waf_rule_hits(
        namespace: Namespace,
        ctx: Context,
        start: TimeSpec = "24h",
        end: TimeSpec | None = None,
        group_by: Annotated[list[WafMetricLabel], Field(min_length=1, max_length=4)] = ["RULE_ID", "VIRTUAL_HOST"],  # noqa: B006
        filters: Annotated[list[WafLabelFilter] | None, Field(max_length=10)] = None,
        top_k: TopK = 20,
    ) -> dict:
        """How many times each WAF rule (signature) matched over the window, per load balancer or any
        other label (RULE_ID, VIRTUAL_HOST, RULE_SEVERITY, RULE_TAG, WAF_MODE, BOT_NAME...). Sorted by
        hits: the top rules on a single load balancer are the usual false positive candidates."""
        rt.require_namespace(namespace)
        start_s, end_s = time_window(rt.settings, start, end)
        minutes = max(1, int((parse_time(end_s) - parse_time(start_s)).total_seconds() // 60))
        body = {"namespace": namespace, "start_time": start_s, "end_time": end_s,
                "step": f"{minutes}m", "range": f"{minutes}m",  # one data point covering the whole window
                "group_by": list(dict.fromkeys(group_by)),
                "label_filter": [{"label": f.label, "op": f.op, "value": f.value} for f in filters or []]}
        method, path = catalog.data_path("waf.rule_hits", namespace=namespace)
        payload = await rt.xc(method, path, body=body)
        series = payload.get("data") if isinstance(payload, dict) else None
        rows = []
        for item in series if isinstance(series, list) else []:
            if not isinstance(item, dict):
                continue
            ident = item.get("id") if isinstance(item.get("id"), dict) else {}
            metrics = item.get("metric") if isinstance(item.get("metric"), list) else []
            hits = sum(_number(m.get("value")) for m in metrics if isinstance(m, dict))
            rows.append({"labels": {sanitize.text(k, 40): sanitize.text(v, 120) for k, v in list(ident.items())[:12]},
                         "hits": hits})
        rows.sort(key=lambda r: r["hits"], reverse=True)
        return sanitize.envelope("get_waf_rule_hits", rows[:top_k], namespace=namespace,
                                 window={"start": start_s, "end": end_s}, series=len(rows),
                                 truncated=len(rows) > top_k)

    # --- load balancer performance (console: Overview > Performance) ---------------------
    @rt.tool(mcp, ToolClass.READ, title="Load balancer performance")
    async def get_lb_performance(
        namespace: Namespace,
        ctx: Context,
        start: TimeSpec = "1h",
        end: TimeSpec | None = None,
        metrics: Annotated[list[PerfMetric], Field(min_length=1, max_length=8)] = [  # noqa: B006
            "HTTP_REQUEST_RATE", "HTTP_ERROR_RATE_4XX", "HTTP_ERROR_RATE_5XX", "HTTP_RESPONSE_LATENCY_PERCENTILE_90"],
        virtual_host: Annotated[str | None, StringConstraints(min_length=1, max_length=100, pattern=XC_NAME_PATTERN),
                                Field(description="Only this virtual host (an HTTP LB 'shop' is usually "
                                                  "'ves-io-http-loadbalancer-shop').")] = None,
        include_healthscore: bool = True,
        top_k: TopK = 20,
    ) -> dict:
        """Performance of the HTTP load balancers of a namespace over a window, like the console's
        Overview > Performance: request rate, 4xx/5xx error rates, latency percentiles, RTT... per
        virtual host, plus health scores (overall, performance, security) with their reason."""
        rt.require_namespace(namespace)
        start_s, end_s = time_window(rt.settings, start, end)
        minutes = max(1, int((parse_time(end_s) - parse_time(start_s)).total_seconds() // 60))
        wanted = list(dict.fromkeys(metrics))
        node: dict[str, Any] = {"metric": {"downstream": wanted, "upstream": wanted}}
        if include_healthscore:
            node["healthscore"] = {"types": ["HEALTHSCORE_OVERALL", "HEALTHSCORE_PERFORMANCE", "HEALTHSCORE_SECURITY"]}
        filters = [{"label": "LABEL_VHOST_TYPE", "op": "EQ", "value": "HTTP_LOAD_BALANCER"}]
        if virtual_host:
            filters.append({"label": "LABEL_VHOST", "op": "EQ", "value": virtual_host})
        body = {"namespace": namespace, "start_time": start_s, "end_time": end_s,
                "step": f"{minutes}m", "range": f"{minutes}m", "group_by": ["VHOST"],
                "label_filter": filters, "field_selector": {"node": node}}
        method, path = catalog.data_path("graph.service", namespace=namespace)
        payload = await rt.xc(method, path, body=body)
        graph = payload.get("data") if isinstance(payload, dict) and isinstance(payload.get("data"), dict) else {}
        nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
        rows = [_perf_row(n) for n in nodes if isinstance(n, dict)]
        rows.sort(key=lambda r: _perf_value(r, "HTTP_REQUEST_RATE"), reverse=True)
        return sanitize.envelope("get_lb_performance", rows[:top_k], namespace=namespace,
                                 window={"start": start_s, "end": end_s}, virtual_hosts=len(rows),
                                 truncated=len(rows) > top_k)

    # --- TLS certificate expiry ---------------------------------------------------------
    async def _get_all(kind_name: str, namespace: str) -> tuple[list[tuple[str, dict[str, Any]]], bool]:
        """GET every object of a kind in a namespace (max 50). Returns (objects, complete)."""
        k = catalog.kind(kind_name)
        try:
            listing = await rt.xc("GET", catalog.kind_path(k, "list", namespace=namespace))
        except SecureError:
            return [], False
        items = listing.get("items", []) if isinstance(listing, dict) else []
        names = [i["name"] for i in items if isinstance(i, dict) and isinstance(i.get("name"), str)]
        complete = len(names) <= MAX_SCANNED
        semaphore = asyncio.Semaphore(4)

        async def one(name: str) -> tuple[str, dict[str, Any]] | None:
            nonlocal complete
            async with semaphore:
                try:
                    obj = await rt.xc("GET", catalog.kind_path(k, "get", namespace=namespace, name=name))
                except SecureError:
                    complete = False
                    return None
            spec = obj.get("spec") if isinstance(obj, dict) and isinstance(obj.get("spec"), dict) else {}
            return name, spec

        results = await asyncio.gather(*(one(n) for n in names[:MAX_SCANNED]))
        return [r for r in results if r is not None], complete

    @rt.tool(mcp, ToolClass.READ, title="TLS certificate expiry")
    async def list_certificate_expiry(
        namespace: Namespace,
        ctx: Context,
        within_days: Annotated[int | None, Field(
            ge=0, le=3650, description="Only certificates expiring within this many days (expired included).")] = None,
        include_auto_certs: bool = True,
        include_chains: bool = False,
    ) -> dict:
        """TLS certificates of a namespace sorted by expiry: name, CN, SANs, issuer, expiry date, days
        left and the load balancers using them. Covers certificate objects, the automatic certificates of
        HTTP load balancers and, optionally, intermediate certificate chains. Private keys are never read
        out. Useful before and after a renewal."""
        rt.require_namespace(namespace)
        now = datetime.now(UTC)
        rows: list[dict[str, Any]] = []
        complete = True
        sources = [("certificate", "certificate")] + ([("certificate_chain", "chain")] if include_chains else [])
        for kind_name, source in sources:
            objects, ok = await _get_all(kind_name, namespace)
            complete = complete and ok
            for name, spec in objects:
                infos = spec.get("infos") if isinstance(spec.get("infos"), list) else []
                used_by = [f"http_loadbalancer/{r['name']}" for r in map(sanitize.ref, spec.get("http_loadbalancers")
                                                                         or []) if r]
                used_by += [f"tcp_loadbalancer/{r['name']}" for r in map(sanitize.ref, spec.get("tcp_loadbalancers")
                                                                         or []) if r]
                for info in infos[:10]:
                    if isinstance(info, dict):
                        rows.append(_cert_row(source, name, info.get("common_name"),
                                              info.get("subject_alternative_names"), info.get("issuer"),
                                              info.get("expiry"), used_by[:50], now))
        if include_auto_certs:
            lbs, ok = await _get_all("http_loadbalancer", namespace)
            complete = complete and ok
            for name, spec in lbs:
                auto = spec.get("auto_cert_info")
                if isinstance(auto, dict) and (auto.get("auto_cert_expiry") or auto.get("auto_cert_subject")):
                    row = _cert_row("lb_auto_cert", name, auto.get("auto_cert_subject"), None,
                                    auto.get("auto_cert_issuer"), auto.get("auto_cert_expiry"),
                                    [f"http_loadbalancer/{sanitize.text(name, 63)}"], now)
                    row["state"] = sanitize.text(auto.get("auto_cert_state"), 60)
                    rows.append(row)
        if within_days is not None:
            rows = [r for r in rows if r["days_left"] is None or r["days_left"] <= within_days]
        rows.sort(key=lambda r: (r["days_left"] is None, r["days_left"] if r["days_left"] is not None else 0))
        return sanitize.envelope(
            "list_certificate_expiry", rows, namespace=namespace,
            expired=sum(1 for r in rows if r["days_left"] is not None and r["days_left"] < 0),
            unknown_expiry=sum(1 for r in rows if r["days_left"] is None),
            incomplete=not complete,
        )

    # --- alerts --------------------------------------------------------------------------
    def _alert_filter(alertname: str | None, severity: str | None) -> str | None:
        matchers = [AlertMatcher(field=f, value=v) for f, v in (("alertname", alertname), ("severity", severity)) if v]
        return build_query(matchers) if matchers else None

    @rt.tool(mcp, ToolClass.READ, title="Active alerts")
    async def list_alerts(
        namespace: Namespace,
        ctx: Context,
        alertname: AlertValue = None,
        severity: AlertValue = None,
        include_inactive: bool = False,
    ) -> dict:
        """Alerts currently firing in a namespace (optionally filtered by alert name or severity), to
        put a security investigation in context."""
        rt.require_namespace(namespace)
        params: dict[str, Any] = {}
        if include_inactive:
            params["inactive"] = "true"
        query = _alert_filter(alertname, severity)
        if query:
            params["filter"] = query
        method, path = catalog.data_path("alerts.list", namespace=namespace)
        payload = await rt.xc(method, path, params=params or None)
        raw = payload.get("data") if isinstance(payload, dict) else None
        alerts = _alert_items(raw)
        data = [_project_alert(a) for a in alerts[: rt.settings.max_events]]
        return sanitize.envelope("list_alerts", data, namespace=namespace, returned=len(data),
                                 truncated=len(alerts) > len(data))

    @rt.tool(mcp, ToolClass.READ, title="Alerts history")
    async def query_alerts_history(
        namespace: Namespace,
        ctx: Context,
        start: TimeSpec = "24h",
        end: TimeSpec | None = None,
        alertname: AlertValue = None,
        severity: AlertValue = None,
    ) -> dict:
        """Alerts raised in a namespace over a time window."""
        rt.require_namespace(namespace)
        start_s, end_s = time_window(rt.settings, start, end)
        params: dict[str, Any] = {"start_time": start_s, "end_time": end_s}
        query = _alert_filter(alertname, severity)
        if query:
            params["filter"] = query
        method, path = catalog.data_path("alerts.history", namespace=namespace)
        payload = await rt.xc(method, path, params=params)
        alerts = _alert_items(payload.get("alerts") if isinstance(payload, dict) else None)
        data = [_project_alert(a) for a in alerts[: rt.settings.max_events]]
        return sanitize.envelope("query_alerts_history", data, namespace=namespace,
                                 window={"start": start_s, "end": end_s}, returned=len(data),
                                 total_hits=sanitize.text(payload.get("total_hits") if isinstance(payload, dict)
                                                          else None, 20))


MAX_SCANNED = 50
XC_NAME_PATTERN = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"


def _last_value(feature: Any) -> float | None:
    raw = feature.get("raw") if isinstance(feature, dict) else None
    points = [p for p in raw if isinstance(p, dict)] if isinstance(raw, list) else []
    return _number(points[-1].get("value")) if points else None


def _perf_row(node: dict[str, Any]) -> dict[str, Any]:
    ident = node.get("id") if isinstance(node.get("id"), dict) else {}
    data = node.get("data") if isinstance(node.get("data"), dict) else {}
    metric = data.get("metric") if isinstance(data.get("metric"), dict) else {}
    row: dict[str, Any] = {
        "virtual_host": sanitize.text(ident.get("vhost"), 120),
        "type": sanitize.text(ident.get("virtual_host_type"), 40),
        "vip": sanitize.text(ident.get("vip"), 64),
        "site": sanitize.text(ident.get("site"), 63),
    }
    for direction in ("downstream", "upstream"):
        values: dict[str, Any] = {}
        for item in metric.get(direction, []) if isinstance(metric.get(direction), list) else []:
            if isinstance(item, dict) and isinstance(item.get("type"), str):
                values[sanitize.text(item["type"], 60)] = {"value": _last_value(item.get("value")),
                                                          "unit": sanitize.text(item.get("unit"), 30)}
        row[direction] = values
    health = data.get("healthscore") if isinstance(data.get("healthscore"), dict) else {}
    row["healthscore"] = {
        sanitize.text(h.get("type"), 40): {"value": _last_value({"raw": h.get("value")}),
                                           "reason": sanitize.text(h.get("reason"), 200)}
        for h in (health.get("data") or [])[:6] if isinstance(h, dict)
    }
    return row


def _perf_value(row: dict[str, Any], metric: str) -> float:
    for direction in ("downstream", "upstream"):
        value = row.get(direction, {}).get(metric, {}).get("value")
        if isinstance(value, float):
            return value
    return -1.0


def _cert_row(source: str, name: str, cn: Any, sans: Any, issuer: Any, expiry: Any, used_by: list[str],
              now: datetime) -> dict[str, Any]:
    days_left = None
    if isinstance(expiry, str) and expiry:
        try:
            when = datetime.fromisoformat(expiry.strip().replace("Z", "+00:00"))
            when = when if when.tzinfo else when.replace(tzinfo=UTC)
            days_left = (when - now).days
        except ValueError:
            days_left = None
    return {
        "source": source,
        "name": sanitize.text(name, 63),
        "common_name": sanitize.text(cn, 253),
        "subject_alternative_names": [sanitize.text(s, 253) for s in sans[:20]] if isinstance(sans, list) else [],
        "issuer": sanitize.text(issuer, 200),
        "expiry": sanitize.text(expiry, 40),
        "days_left": days_left,
        "used_by": used_by,
    }


def _number(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if number == number and abs(number) != float("inf") else 0.0


def _alert_items(raw: Any) -> list[Any]:
    """Alerts come as a list or as a JSON string holding one (``data`` is typed string)."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return []
    if isinstance(raw, dict):
        raw = raw.get("alerts") or raw.get("data") or []
    return [a for a in raw if isinstance(a, dict | str)] if isinstance(raw, list) else []


def _project_alert(alert: Any) -> dict[str, Any]:
    """Alert fields that help an investigation; free text (annotations) is bounded and single-line."""
    if isinstance(alert, str):
        try:
            alert = json.loads(alert)
        except ValueError:
            return {"unparsed": True}
    if not isinstance(alert, dict):
        return {"unparsed": True}
    labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
    annotations = alert.get("annotations") if isinstance(alert.get("annotations"), dict) else {}
    status = alert.get("status")
    return {
        "labels": {sanitize.text(k, 40): sanitize.text(v, 120) for k, v in list(labels.items())[:16]},
        "summary": sanitize.text(annotations.get("summary"), 200),
        "description": sanitize.text(annotations.get("description"), 300),
        "state": sanitize.text(status.get("state") if isinstance(status, dict) else status, 40),
        "starts_at": sanitize.text(alert.get("startsAt") or alert.get("starts_at"), 40),
        "ends_at": sanitize.text(alert.get("endsAt") or alert.get("ends_at"), 40),
    }


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
