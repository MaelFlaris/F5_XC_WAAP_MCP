"""Write tools (registered only with F5XC_MCP_MODE=write and F5XC_MCP_ENABLE_WRITES=true).

Every change is a two-step flow:

  1. a ``plan_*`` tool reads the current object, builds the exact request body
     server side and returns its complete diff, its SHA-256 and a single-use
     ``plan_id`` (TTL a few minutes);
  2. ``apply_plan(plan_id)`` shows the human, through MCP elicitation, the same
     complete diff, the body hash and a HIGH RISK banner when the change lowers
     protection; then checks the object did not change since the plan and sends
     the request.

Scope is deliberately narrow: targeted plan tools for the common WAAP actions,
and creation limited to kinds that have no effect until something references
them. There is no generic replace and no delete. Protected namespaces (system,
shared) are never written.
"""

import asyncio
import copy
import ipaddress
import json
import os
import re
import time
from pathlib import Path
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel, Field, StringConstraints

from .. import catalog, sanitize
from ..errors import Code, SecureError
from ..plans import Plan, canonical_hash, diff, render
from ..psl import is_public_suffix
from ..runtime import Runtime, ToolClass
from .common import XC_NAME, Namespace, ObjectName

MAX_SPEC_BYTES = 65_536
Labels = Annotated[
    dict[Annotated[str, StringConstraints(max_length=63, pattern=r"^[A-Za-z0-9_./\-]+$")],
         Annotated[str, StringConstraints(max_length=63, pattern=r"^[A-Za-z0-9_.\-]*$")]] | None,
    Field(max_length=20),
]
Description = Annotated[str | None, StringConstraints(max_length=256, pattern=r"^[^\x00-\x1f\x7f]*$")]
Prefix = Annotated[str, StringConstraints(max_length=43)]
# Keys accepted in a WAF exclusion rule (policySimpleWafExclusionRule in the API reference).
WAF_RULE_KEYS = frozenset({
    "metadata", "any_domain", "exact_value", "suffix_value", "any_path", "path_prefix", "path_regex",
    "methods", "app_firewall_detection_control", "expiration_timestamp",
})
# Kinds that can be created: none of them changes traffic handling until an
# existing load balancer or namespace policy list references it (which then
# goes through a reviewed plan of its own).
CREATABLE_KINDS = (
    "app_firewall", "healthcheck", "ip_prefix_set", "rate_limiter", "rate_limiter_policy", "service_policy",
    "waf_exclusion_policy",
)
CreatableKind = Literal[CREATABLE_KINDS]  # type: ignore[valid-type]

WRITABLE_METADATA = ("labels", "annotations", "description", "disable")

# Creation: kinds whose objects could already reference the new name (XC keeps
# references to objects that do not exist, cf. the GET_RSP_FORMAT_BROKEN_REFERENCES
# response format). They are scanned in the target namespace before planning.
REFERENCERS: dict[str, tuple[str, ...]] = {
    "app_firewall": ("http_loadbalancer", "cdn_loadbalancer"),
    "waf_exclusion_policy": ("http_loadbalancer", "cdn_loadbalancer"),
    "service_policy": ("http_loadbalancer", "cdn_loadbalancer", "tcp_loadbalancer"),
    "rate_limiter_policy": ("http_loadbalancer", "cdn_loadbalancer"),
    "rate_limiter": ("http_loadbalancer", "cdn_loadbalancer", "rate_limiter_policy"),
    "ip_prefix_set": ("service_policy", "http_loadbalancer", "cdn_loadbalancer"),
    "healthcheck": ("origin_pool",),
}
MAX_SCANNED_PER_KIND = 50

LB_DOWNGRADES = {
    "disable_waf": "WAF disabled on the load balancer",
    "disable_bot_defense": "bot defense disabled",
    "disable_ip_reputation": "IP reputation disabled",
    "disable_malicious_user_detection": "malicious user detection disabled",
    "disable_rate_limit": "rate limiting disabled",
    "disable_api_discovery": "API discovery disabled",
    "no_service_policies": "service policies removed",
}


class Confirmation(BaseModel):
    approve: bool = Field(description="Approve this change in F5 Distributed Cloud.")
    object_name: str = Field(description="Type the name of the object to confirm.")


class HighRiskConfirmation(Confirmation):
    hash_prefix: str = Field(description="HIGH RISK: type the first 8 characters of the body SHA-256 shown above.")


def check_spec(k: catalog.Kind, spec: dict[str, Any]) -> None:
    if len(json.dumps(spec)) > MAX_SPEC_BYTES:
        raise SecureError(Code.INVALID_ARGUMENT, "Spec too large.")
    unknown = sorted(set(spec) - set(k.spec_fields))
    if unknown:
        raise SecureError(Code.INVALID_ARGUMENT, f"Unknown spec fields for {k.name}: {', '.join(unknown[:10])}.")


def set_oneof(k: catalog.Kind, spec: dict[str, Any], group: str, choice: str, value: Any) -> None:
    for option in k.oneofs[group]:
        spec.pop(option, None)
    spec[choice] = value


def _exclusion_rules(node: Any, out: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """WAF exclusion rules (policySimpleWafExclusionRule) found anywhere in a spec."""
    out = [] if out is None else out
    if isinstance(node, dict):
        if "app_firewall_detection_control" in node or "waf_skip_processing" in node:
            out.append(node)
            return out
        for value in node.values():
            _exclusion_rules(value, out)
    elif isinstance(node, list):
        for value in node:
            _exclusion_rules(value, out)
    return out


MAX_PRECISE_SIGNATURES = 5
_PLAIN = re.compile(r"[A-Za-z0-9_.\-/\[\]@+]{1,120}")  # e-mails stay readable


def shown(value: Any) -> str:
    """A model- or XC-supplied value as it may appear in a risk reason: kept as is when
    plain, JSON-escaped otherwise, so it cannot add lines to the confirmation banner."""
    text = str(value)
    return text if _PLAIN.fullmatch(text) else json.dumps(text, ensure_ascii=True)[:120]


def exclusion_rule_risks(rule: dict[str, Any]) -> list[str]:
    """A WAF exclusion is low risk only when it targets precise signatures on a precise
    domain and path. Anything broader effectively switches part of the WAF off.
    Field names: policySimpleWafExclusionRule / policyAppFirewallDetectionControl."""
    meta = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
    label = f"WAF exclusion {shown(meta.get('name', '?'))}"
    reasons = []
    if "waf_skip_processing" in rule:
        reasons.append(f"{label} skips all WAF processing")
    if "any_domain" in rule or not any(k in rule for k in ("exact_value", "suffix_value")):
        reasons.append(f"{label} applies to any domain")
    if "any_path" in rule or not any(k in rule for k in ("path_prefix", "path_regex")):
        reasons.append(f"{label} applies to any path")
    if "path_regex" in rule:
        reasons.append(f"{label} uses a path regex (scope hard to review)")
    prefix = rule.get("path_prefix")
    if isinstance(prefix, str) and prefix.strip("/") == "":
        reasons.append(f"{label} path prefix {shown(prefix)} covers every path")
    suffix = rule.get("suffix_value")
    # Public Suffix List (ICANN + private sections): "com", "gouv.fr", "co.uk", "github.io"...
    if isinstance(suffix, str) and is_public_suffix(suffix):
        reasons.append(f"{label} domain suffix {shown(suffix)} is a public suffix (sites of unrelated owners)")
    exact = rule.get("exact_value")
    if isinstance(exact, str) and "*" in exact:
        reasons.append(f"{label} domain {shown(exact)} contains a wildcard")
    control = rule.get("app_firewall_detection_control")
    control = control if isinstance(control, dict) else {}
    for key, what in (("exclude_attack_type_contexts", "whole attack types"),
                      ("exclude_violation_contexts", "violations"),
                      ("exclude_bot_name_contexts", "bot names")):
        if control.get(key):
            reasons.append(f"{label} excludes {what}")
    signatures = control.get("exclude_signature_contexts") or []
    if any(isinstance(sig, dict) and sig.get("signature_id") in (0, "0") for sig in signatures):
        reasons.append(f"{label} excludes ALL signatures (signature_id 0)")
    if isinstance(signatures, list) and len(signatures) > MAX_PRECISE_SIGNATURES:
        reasons.append(f"{label} excludes {len(signatures)} signatures at once "
                       f"(more than {MAX_PRECISE_SIGNATURES})")
    return reasons


def assess_risks(kind: str, before: dict[str, Any], after: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
    """Reasons for a HIGH RISK banner (changes that lower protection or widen access)."""
    risks: list[str] = []
    paths = [op["path"] for op in ops]
    if kind in ("http_loadbalancer", "cdn_loadbalancer"):
        risks += [label for key, label in LB_DOWNGRADES.items() if key in after and key not in before]
        if any(p.startswith("spec.trusted_clients") for p in paths):
            risks.append("trusted clients changed: these clients bypass security controls")
    if kind in ("http_loadbalancer", "cdn_loadbalancer", "waf_exclusion_policy"):
        existing = {canonical_hash(rule) for rule in _exclusion_rules(before)}
        for rule in _exclusion_rules(after):
            if canonical_hash(rule) not in existing:  # new or modified rule
                risks += exclusion_rule_risks(rule)
    if kind == "app_firewall" and "monitoring" in after and "monitoring" not in before and before:
        risks.append("App Firewall switched to monitoring: attacks are no longer blocked")
    if kind == "ip_prefix_set" and before and ops:
        risks.append("IP prefix set changed: it may be used as an allow-list (trusted clients, allow rules); "
                     "the server cannot tell how it is referenced")
    return risks


def register(mcp: FastMCP, rt: Runtime) -> None:
    def ensure_writes_enabled() -> None:
        kill = rt.settings.write_kill_switch
        if kill and os.path.exists(kill):
            raise SecureError(Code.WRITES_DISABLED)

    def writable(kind_name: str, namespace: str) -> catalog.Kind:
        ensure_writes_enabled()
        rt.require_namespace(namespace, write=True)
        k = catalog.kind(kind_name)
        if not k.writable:
            raise SecureError(Code.KIND_NOT_WRITABLE)
        return k

    async def current(k: catalog.Kind, namespace: str, name: str) -> tuple[dict[str, Any], dict[str, Any], str]:
        """Current (metadata, spec, version) in replace form.

        ``version`` fingerprints everything the PUT sends back (spec and the
        writable metadata: labels, annotations, description, disable) plus the
        object uid, so a concurrent edit, a disable or a delete-and-recreate
        between plan and apply makes the plan stale. The published API has no
        version precondition on PUT: the remaining check-to-PUT window is
        documented in docs/THREAT_MODEL.md."""
        obj = await rt.xc("GET", catalog.kind_path(k, "get", namespace=namespace, name=name),
                          params={"response_format": "GET_RSP_FORMAT_FOR_REPLACE"})
        if not isinstance(obj, dict):
            raise SecureError(Code.RESPONSE_INVALID)
        form = obj.get("replace_form") if isinstance(obj.get("replace_form"), dict) else obj
        metadata = form.get("metadata") if isinstance(form.get("metadata"), dict) else {}
        spec = form.get("spec") if isinstance(form.get("spec"), dict) else {}
        system = obj.get("system_metadata") if isinstance(obj.get("system_metadata"), dict) else {}
        version = canonical_hash({
            "metadata": {key: metadata.get(key) for key in WRITABLE_METADATA},
            "spec": spec,
            "uid": system.get("uid"),
        })
        return metadata, spec, version

    def make_plan(*, k: catalog.Kind, operation: Literal["create", "replace"], namespace: str, name: str,
                  metadata: dict[str, Any], before: dict[str, Any], after: dict[str, Any], summary: str,
                  version: str | None = None, extra_risks: list[str] | None = None) -> dict[str, Any]:
        ops = diff(before, after)
        if not ops and operation == "create":
            ops = [{"op": "add", "path": "spec", "after": "{}"}]  # creating an object is a change even if empty
        if not ops:
            raise SecureError(Code.INVALID_ARGUMENT, "The change would not modify the object.")
        risks = assess_risks(k.name, before, after, ops) + (extra_risks or [])
        if operation == "replace":
            meta = {key: metadata[key] for key in WRITABLE_METADATA if key in metadata}
            method, path = "PUT", catalog.kind_path(k, "replace", namespace=namespace, name=name)
        else:
            meta = metadata
            method, path = "POST", catalog.kind_path(k, "create", namespace=namespace)
        body = {"metadata": {**meta, "name": name, "namespace": namespace}, "spec": after}
        plan = rt.plans.create(
            identity=rt.identity().key, operation=operation, kind=k.name, namespace=namespace, name=name,
            method=method, path=path, body=body,
            base_version=version,
            summary=summary, diff=ops, risks=risks, before=before if operation == "replace" else None,
        )
        rt.annotate(plan_id=plan.plan_id)
        rt.audit_event("plan_created", plan_id=plan.plan_id, operation=operation, kind=k.name, namespace=namespace,
                       target=name, body_sha256=plan.body_sha256, risk="high" if risks else "standard",
                       risks=risks, diff_ops=len(ops))
        return sanitize.envelope(
            "plan",
            {"plan_id": plan.plan_id, "operation": operation, "kind": k.name, "namespace": namespace, "name": name,
             "summary": summary, "risk": "HIGH" if risks else "standard", "risks": risks,
             "body_sha256": plan.body_sha256, "diff": ops, "diff_text": render(ops), "diff_complete": True},
            expires_in_s=rt.settings.plan_ttl_s,
            next_step="Show the diff to the user, then call apply_plan(plan_id). The user will see the same "
                      "diff and hash in the confirmation prompt.",
        )

    async def existing_references(kind: str, namespace: str, name: str) -> tuple[list[str], bool]:
        """Objects of the namespace that already reference ``name``. Returns
        (descriptions, complete); complete is False when the scan was truncated
        or a read failed, which the caller reports as a risk."""
        found: list[str] = []
        complete = True

        if kind == "service_policy":
            try:
                method, path = catalog.data_path("namespace.active_service_policies", namespace=namespace)
                active = await rt.xc(method, path)
                policies = active.get("service_policies", []) if isinstance(active, dict) else []
                if any(isinstance(p, dict) and p.get("name") == name
                       and p.get("namespace") in (None, "", namespace) for p in policies):
                    found.append(f"the active service policies of namespace {namespace}")
            except SecureError:
                complete = False
        semaphore = asyncio.Semaphore(4)

        async def scan(rk: catalog.Kind, obj_name: str) -> None:
            nonlocal complete
            async with semaphore:
                try:
                    obj = await rt.xc("GET", catalog.kind_path(rk, "get", namespace=namespace, name=obj_name))
                except SecureError:
                    complete = False
                    return
            spec = obj.get("spec") if isinstance(obj, dict) and isinstance(obj.get("spec"), dict) else {}
            fields, scanned_all = sanitize.find_references_to(spec, name, namespace)
            if not scanned_all:
                complete = False
            found.extend(f"{rk.name} {namespace}/{shown(obj_name)} ({shown(field)})" for field in fields)

        for referrer_kind in REFERENCERS.get(kind, ()):
            rk = catalog.kind(referrer_kind)
            try:
                listing = await rt.xc("GET", catalog.kind_path(rk, "list", namespace=namespace))
            except SecureError:
                complete = False
                continue
            items = listing.get("items", []) if isinstance(listing, dict) else []
            names = [i["name"] for i in items if isinstance(i, dict) and isinstance(i.get("name"), str)]
            if len(names) > MAX_SCANNED_PER_KIND:
                complete = False
            await asyncio.gather(*(scan(rk, n) for n in names[:MAX_SCANNED_PER_KIND]))
        return sorted(set(found)), complete

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: attach or detach the WAF of a load balancer", idempotent=False)
    async def plan_set_lb_waf(
        namespace: Namespace,
        name: ObjectName,
        ctx: Context,
        app_firewall: Annotated[str | None, StringConstraints(max_length=63, pattern=XC_NAME),
                                Field(description="App Firewall to attach; omit to disable the WAF.")] = None,
        app_firewall_namespace: Annotated[
            str | None, StringConstraints(max_length=63, pattern=XC_NAME),
            Field(description="Namespace of the App Firewall (default: same as the load balancer; must be "
                              "allow-listed).")] = None,
    ) -> dict:
        """Prepare attaching an App Firewall to an HTTP load balancer (or disabling its WAF).
        Returns the complete diff and a plan_id; nothing changes until apply_plan."""
        k = writable("http_loadbalancer", namespace)
        extra: list[str] = []
        metadata, before, version = await current(k, namespace, name)
        after = copy.deepcopy(before)
        if app_firewall:
            fw_namespace = app_firewall_namespace or namespace
            rt.require_namespace(fw_namespace)
            fw = await rt.xc("GET", catalog.kind_path(catalog.kind("app_firewall"), "get", namespace=fw_namespace,
                                                      name=app_firewall))
            fw_spec = fw.get("spec") if isinstance(fw, dict) and isinstance(fw.get("spec"), dict) else {}
            if "monitoring" in fw_spec:
                extra.append(f"App Firewall {app_firewall} is in monitoring mode: attacks will not be blocked")
            set_oneof(k, after, "waf_choice", "app_firewall", {"name": app_firewall, "namespace": fw_namespace})
            summary = f"attach App Firewall {fw_namespace}/{app_firewall} to load balancer {name}"
        else:
            set_oneof(k, after, "waf_choice", "disable_waf", {})
            summary = f"DISABLE the WAF of load balancer {name}"
        return make_plan(k=k, operation="replace", namespace=namespace, name=name, metadata=metadata,
                         before=before, after=after, version=version, summary=summary, extra_risks=extra)

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: WAF blocking or monitoring mode", idempotent=False)
    async def plan_set_waf_mode(
        namespace: Namespace, name: ObjectName, mode: Literal["blocking", "monitoring"], ctx: Context,
    ) -> dict:
        """Prepare switching an App Firewall between blocking and monitoring mode."""
        k = writable("app_firewall", namespace)
        metadata, before, version = await current(k, namespace, name)
        after = copy.deepcopy(before)
        set_oneof(k, after, "enforcement_mode_choice", mode, {})
        return make_plan(k=k, operation="replace", namespace=namespace, name=name, metadata=metadata,
                         before=before, after=after, version=version, summary=f"set App Firewall {name} to {mode} mode")

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: add/remove IP prefixes", idempotent=False)
    async def plan_update_ip_prefix_set(
        namespace: Namespace,
        name: ObjectName,
        ctx: Context,
        add: Annotated[list[Prefix] | None, Field(max_length=50)] = None,
        remove: Annotated[list[Prefix] | None, Field(max_length=50)] = None,
        comment: Annotated[str | None, StringConstraints(max_length=100, pattern=r"^[A-Za-z0-9 _.,:\-]*$")] = None,
    ) -> dict:
        """Prepare adding/removing IPv4 prefixes in an ip_prefix_set (typically referenced by a service
        policy to block or allow clients). Prefixes are validated and must be at least as specific as the
        server minimum (default /16)."""
        k = writable("ip_prefix_set", namespace)
        minimum = rt.settings.min_ipv4_prefix_len

        def normalize(values: list[str] | None) -> list[str]:
            out = []
            for value in values or []:
                try:
                    network = ipaddress.IPv4Network(value.strip(), strict=True)
                except ValueError as exc:
                    raise SecureError(Code.INVALID_ARGUMENT,
                                      f"Invalid IPv4 prefix {value[:43]!r} (host bits must be zero).") from exc
                if network.prefixlen < minimum:
                    raise SecureError(Code.INVALID_ARGUMENT, f"Prefix {network} is broader than /{minimum}.")
                out.append(str(network))
            return out

        to_add, to_remove = normalize(add), set(normalize(remove))
        if not to_add and not to_remove:
            raise SecureError(Code.INVALID_ARGUMENT, "Nothing to add or remove.")
        metadata, before, version = await current(k, namespace, name)
        after = copy.deepcopy(before)
        entries = [e for e in after.get("ipv4_prefixes", []) if isinstance(e, dict)]
        entries = [e for e in entries if e.get("ipv4_prefix") not in to_remove]
        present = {e.get("ipv4_prefix") for e in entries}
        for prefix in to_add:
            if prefix not in present:
                entries.append({"ipv4_prefix": prefix, **({"description": comment} if comment else {})})
        after["ipv4_prefixes"] = entries
        return make_plan(k=k, operation="replace", namespace=namespace, name=name, metadata=metadata,
                         before=before, after=after, version=version,
                         summary=f"ip_prefix_set {name}: +{len(to_add)} / -{len(to_remove)} prefixes")

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: add a WAF exclusion rule to a load balancer", idempotent=False)
    async def plan_add_waf_exclusion_rule(
        namespace: Namespace,
        name: ObjectName,
        rule: Annotated[dict[str, Any], Field(description="The waf_exclusion_rule returned by "
                                                          "suggest_waf_exclusion_rule (may be edited).")],
        ctx: Context,
    ) -> dict:
        """Prepare appending a WAF exclusion rule to the inline WAF exclusion rules of an HTTP load
        balancer (false positive handling). Rules that skip all WAF processing are refused."""
        k = writable("http_loadbalancer", namespace)
        if "waf_skip_processing" in rule:
            raise SecureError(Code.INVALID_ARGUMENT, "Rules skipping all WAF processing are not allowed; "
                                                     "exclude specific signatures/violations instead.")
        unknown = set(rule) - WAF_RULE_KEYS
        if unknown:
            raise SecureError(Code.INVALID_ARGUMENT, f"Unexpected rule fields: {', '.join(sorted(unknown)[:10])}.")
        if "app_firewall_detection_control" not in rule:
            raise SecureError(Code.INVALID_ARGUMENT, "The rule needs app_firewall_detection_control.")
        meta = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
        if not isinstance(meta.get("name"), str) or not catalog.XC_NAME_RE.fullmatch(meta["name"]):
            raise SecureError(Code.INVALID_ARGUMENT, "rule.metadata.name must be a valid XC name.")
        if len(json.dumps(rule)) > 16_384:
            raise SecureError(Code.INVALID_ARGUMENT, "Rule too large.")
        metadata, before, version = await current(k, namespace, name)
        after = copy.deepcopy(before)
        exclusion = after.get("waf_exclusion") if isinstance(after.get("waf_exclusion"), dict) else {}
        if "waf_exclusion_policy" in exclusion:
            raise SecureError(Code.INVALID_ARGUMENT, "This load balancer uses a waf_exclusion_policy object; "
                                                     "changing it is not supported by this server version.")
        inline = exclusion.get("waf_exclusion_inline_rules")
        rules = list(inline.get("rules", [])) if isinstance(inline, dict) else []
        if any(isinstance(r, dict) and r.get("metadata", {}).get("name") == meta["name"] for r in rules):
            raise SecureError(Code.INVALID_ARGUMENT, "A rule with this name already exists.")
        rules.append(rule)
        after["waf_exclusion"] = {"waf_exclusion_inline_rules": {"rules": rules}}
        return make_plan(k=k, operation="replace", namespace=namespace, name=name, metadata=metadata,
                         before=before, after=after, version=version,
                         summary=f"add WAF exclusion rule {meta['name']} to load balancer {name}")

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: create an object", idempotent=False)
    async def plan_create_object(
        kind: CreatableKind,
        namespace: Namespace,
        name: ObjectName,
        spec: dict[str, Any],
        ctx: Context,
        description: Description = None,
        labels: Labels = None,
    ) -> dict:
        """Prepare creating a new object of a kind that has no effect until referenced (App Firewall,
        service policy, IP prefix set, rate limiter, WAF exclusion policy, health check). Attaching it to a
        load balancer is a separate, reviewed change."""
        k = writable(kind, namespace)
        rt.require_kind_topic(k)
        check_spec(k, spec)
        referrers, complete = await existing_references(kind, namespace, name)
        extra = [f"already referenced by {r}: creating it activates it immediately" for r in referrers]
        if not complete:
            extra.append("the search for existing references was incomplete: the object may become active "
                         "as soon as it is created")
        metadata: dict[str, Any] = {}
        if description:
            metadata["description"] = description
        if labels:
            metadata["labels"] = labels
        return make_plan(k=k, operation="create", namespace=namespace, name=name, metadata=metadata,
                         before={}, after=spec, summary=f"create {kind} {name}", extra_risks=extra)

    @rt.tool(mcp, ToolClass.WRITE, title="Apply a planned change", idempotent=False)
    async def apply_plan(
        plan_id: Annotated[str, StringConstraints(min_length=10, max_length=64, pattern=r"^plan_[A-Za-z0-9_\-]+$")],
        ctx: Context,
    ) -> dict:
        """Apply a change prepared by a plan_* tool. The user is shown the complete diff and body hash and
        must confirm (MCP elicitation); without an elicitation-capable client nothing is applied."""
        rt.annotate(plan_id=plan_id)
        plan = rt.plans.take(plan_id, rt.identity().key)
        rt.annotate(kind=plan.kind, namespace=plan.namespace, target=plan.name, operation=plan.operation,
                    body_sha256=plan.body_sha256)
        k = writable(plan.kind, plan.namespace)
        outcome = await _confirm(ctx, plan)
        rt.audit_event("plan_confirmation", plan_id=plan.plan_id, outcome=outcome, risk="high" if plan.risks
                       else "standard", body_sha256=plan.body_sha256)
        if outcome != "approved":
            raise SecureError(Code.CONFIRMATION_REQUIRED, f"Outcome: {outcome}.")
        status, error = "ok", None
        try:
            if plan.operation == "replace":
                _, _, latest = await current(k, plan.namespace, plan.name)
                if latest != plan.base_version:
                    raise SecureError(Code.PLAN_STALE)
            # The kill switch may have been set while the human was reading the diff.
            ensure_writes_enabled()
            await rt.xc(plan.method, plan.path, body=plan.body)
        except SecureError as exc:
            status, error = "error", str(exc.code)
            raise
        finally:
            # method + path + user + ts: the keys to match this event 1:1 with the XC audit log.
            rt.audit_event("plan_applied", plan_id=plan.plan_id, operation=plan.operation, kind=plan.kind,
                           namespace=plan.namespace, target=plan.name, body_sha256=plan.body_sha256,
                           method=plan.method, path=plan.path, status=status, error_code=error)
        try:
            rollback = save_rollback(plan)
        except (OSError, TypeError, ValueError) as exc:
            # The change IS applied in XC: never report it as failed (the model would retry).
            rollback = False
            rt.audit_event("rollback_failed", plan_id=plan.plan_id, detail=type(exc).__name__)
        return sanitize.envelope("apply_plan", {"applied": True, "plan_id": plan.plan_id, "operation": plan.operation,
                                                "kind": plan.kind, "namespace": plan.namespace, "name": plan.name,
                                                "body_sha256": plan.body_sha256, "summary": plan.summary,
                                                "rollback_available": rollback})

    def rollback_path(plan_id: str) -> Path | None:
        directory = rt.settings.rollback_dir
        return Path(directory) / f"{plan_id}.json" if directory else None

    def save_rollback(plan: Plan) -> bool:
        """Keep the pre-change spec of an applied replace (0700 dir, 0600 file)."""
        path = rollback_path(plan.plan_id)
        if path is None or plan.operation != "replace" or plan.before is None:
            return False
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Secrets never go to disk: they are replaced by a marker and taken back from the
        # live object at revert time (the plan tools never change secret fields).
        record = {"plan_id": plan.plan_id, "applied_at": time.time(), "user": rt.identity().principal.user,
                  "user_uuid": rt.identity().principal.user_uuid,
                  "kind": plan.kind, "namespace": plan.namespace, "name": plan.name,
                  "body_sha256": plan.body_sha256, "before_spec": strip_secrets(plan.before)}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, sort_keys=True)
        rt.audit_event("rollback_saved", plan_id=plan.plan_id, kind=plan.kind, namespace=plan.namespace,
                       target=plan.name)
        return True

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: revert an applied change", idempotent=False)
    async def plan_revert(
        plan_id: Annotated[str, StringConstraints(min_length=10, max_length=64, pattern=r"^plan_[A-Za-z0-9_\-]+$")],
        ctx: Context,
    ) -> dict:
        """Prepare restoring the spec an applied change replaced. The inverse change is a normal plan:
        complete diff, risk banner, human confirmation, stale check. Creations cannot be reverted here."""
        path = rollback_path(plan_id)
        if path is None or not path.is_file():
            raise SecureError(Code.ROLLBACK_UNAVAILABLE)
        record = json.loads(path.read_text(encoding="utf-8"))
        k = writable(record["kind"], record["namespace"])
        metadata, before, version = await current(k, record["namespace"], record["name"])
        after = restore_secrets(record["before_spec"], before)
        author = shown(record.get("user", "?"))
        applied_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(record.get("applied_at", 0))))
        extra = []
        if record.get("user_uuid") != rt.identity().principal.user_uuid:
            extra.append(f"reverts a change applied by another user ({author})")
        rt.annotate(reverts=plan_id, reverted_author=record.get("user"))
        return make_plan(k=k, operation="replace", namespace=record["namespace"], name=record["name"],
                         metadata=metadata, before=before, after=after, version=version,
                         summary=f"REVERT {plan_id} (applied by {author} at {applied_at}) on "
                                 f"{record['kind']} {record['name']}", extra_risks=extra)


SECRET_MARKER = {"__f5xc_mcp_secret_kept_in_xc__": True}


def strip_secrets(node: Any) -> Any:
    """Copy of a spec with every secret replaced by SECRET_MARKER (lossless otherwise)."""
    if isinstance(node, dict):
        return {k: SECRET_MARKER if sanitize.is_secret_key(str(k)) else strip_secrets(v) for k, v in node.items()}
    if isinstance(node, list):
        return [strip_secrets(v) for v in node]
    if isinstance(node, str) and (node.startswith("string:///") or "-----BEGIN" in node):
        return SECRET_MARKER
    return node


def _named(item: Any) -> str | None:
    if isinstance(item, dict):
        meta = item.get("metadata")
        name = meta.get("name") if isinstance(meta, dict) else item.get("name")
        return name if isinstance(name, str) else None
    return None


def restore_secrets(stored: Any, live: Any) -> Any:
    """Put back the secrets of the live object where the record has SECRET_MARKER.
    Refuses when a secret's position cannot be matched unambiguously (a wrong pairing
    would attach one certificate's key to another)."""
    if stored == SECRET_MARKER:
        if live is None or live == SECRET_MARKER:
            raise SecureError(Code.ROLLBACK_UNAVAILABLE, "A secret of the saved state no longer exists.")
        return live
    if isinstance(stored, dict):
        live_dict = live if isinstance(live, dict) else {}
        return {k: restore_secrets(v, live_dict.get(k)) for k, v in stored.items()}
    if isinstance(stored, list):
        live_list = live if isinstance(live, list) else []
        by_name = {_named(i): i for i in live_list if _named(i) is not None}
        out = []
        for index, item in enumerate(stored):
            if not _contains_marker(item):
                out.append(item)
            elif _named(item) is not None and _named(item) in by_name:
                out.append(restore_secrets(item, by_name[_named(item)]))
            elif len(live_list) == len(stored):
                out.append(restore_secrets(item, live_list[index]))
            else:
                raise SecureError(Code.ROLLBACK_UNAVAILABLE, "A secret moved since the change; revert by hand.")
        return out
    return stored


def _contains_marker(node: Any) -> bool:
    if node == SECRET_MARKER:
        return True
    if isinstance(node, dict):
        return any(_contains_marker(v) for v in node.values())
    if isinstance(node, list):
        return any(_contains_marker(v) for v in node)
    return False


def confirmation_message(plan: Plan) -> str:
    banner = ""
    if plan.risks:
        # Each reason on exactly one line, whatever it contains (defence in depth).
        lines = [r if r.isprintable() else json.dumps(r, ensure_ascii=True) for r in plan.risks]
        banner = "!!! HIGH RISK !!!\n" + "\n".join(f"  - {line}" for line in lines) + "\n\n"
    return (
        f"{banner}Change requested in F5 Distributed Cloud: {plan.summary}\n"
        f"Target: {plan.operation} {plan.kind} {plan.namespace}/{plan.name}\n"
        f"Request: {plan.method} {plan.path}\n"
        f"Body SHA-256: {plan.body_sha256}\n"
        f"Complete diff ({len(plan.diff)} change(s)):\n{render(plan.diff)}\n\n"
        f"To approve, type the object name '{plan.name}'"
        + (" and the first 8 characters of the body SHA-256." if plan.risks else ".")
    )


async def _confirm(ctx: Context, plan: Plan) -> str:
    """Ask the human. Returns approved | declined | cancelled | mismatch | unsupported_client."""
    session = ctx.request_context.session
    params = getattr(session, "client_params", None)
    capabilities = getattr(params, "capabilities", None)
    if getattr(capabilities, "elicitation", None) is None:
        return "unsupported_client"
    schema = HighRiskConfirmation if plan.risks else Confirmation
    result = await ctx.elicit(message=confirmation_message(plan), schema=schema)
    if result.action != "accept":
        return "declined" if result.action == "decline" else "cancelled"
    data = getattr(result, "data", None)
    if not isinstance(data, Confirmation) or not data.approve:
        return "declined"
    if data.object_name.strip() != plan.name:
        return "mismatch"
    if plan.risks and (not isinstance(data, HighRiskConfirmation)
                       or data.hash_prefix.strip().lower() != plan.body_sha256[:8]):
        return "mismatch"
    return "approved"
