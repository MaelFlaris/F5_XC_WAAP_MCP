"""Write tools (registered only with F5XC_MCP_MODE=write and F5XC_MCP_ENABLE_WRITES=true).

Every change is a two-step flow:

  1. a ``plan_*`` tool reads the current object, builds the exact request body
     server side, returns a diff and a single-use ``plan_id`` (TTL a few minutes);
  2. ``apply_plan(plan_id)`` asks a human to confirm through MCP elicitation,
     checks the object did not change since the plan, then sends the request.

There is no delete tool. Protected namespaces (system, shared) are never written.
"""

import copy
import hashlib
import ipaddress
import json
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel, Field, StringConstraints

from .. import catalog, sanitize
from ..errors import Code, SecureError
from ..plans import Plan, diff
from ..runtime import Runtime, ToolClass
from .common import XC_NAME, Namespace, ObjectName

MAX_SPEC_BYTES = 262_144
Labels = Annotated[
    dict[Annotated[str, StringConstraints(max_length=63, pattern=r"^[A-Za-z0-9_./\-]+$")],
         Annotated[str, StringConstraints(max_length=63, pattern=r"^[A-Za-z0-9_.\-]*$")]] | None,
    Field(max_length=20),
]
Description = Annotated[str | None, StringConstraints(max_length=256)]
Prefix = Annotated[str, StringConstraints(max_length=43)]
# Keys accepted in a WAF exclusion rule (policySimpleWafExclusionRule in the API reference).
WAF_RULE_KEYS = frozenset({
    "metadata", "any_domain", "exact_value", "suffix_value", "any_path", "path_prefix", "path_regex",
    "methods", "app_firewall_detection_control", "expiration_timestamp",
})


class Confirmation(BaseModel):
    approve: bool = Field(description="Approve this change in F5 Distributed Cloud.")
    object_name: str = Field(description="Type the name of the object to confirm.")


def spec_hash(spec: Any) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


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


def register(mcp: FastMCP, rt: Runtime) -> None:
    def writable(kind_name: str, namespace: str) -> catalog.Kind:
        rt.require_namespace(namespace, write=True)
        k = catalog.kind(kind_name)
        if not k.writable:
            raise SecureError(Code.KIND_NOT_WRITABLE)
        return k

    async def current(k: catalog.Kind, namespace: str, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Current (metadata, spec) in replace form."""
        obj = await rt.xc("GET", catalog.kind_path(k, "get", namespace=namespace, name=name),
                          params={"response_format": "GET_RSP_FORMAT_FOR_REPLACE"})
        if not isinstance(obj, dict):
            raise SecureError(Code.RESPONSE_INVALID)
        form = obj.get("replace_form") if isinstance(obj.get("replace_form"), dict) else obj
        metadata = form.get("metadata") if isinstance(form.get("metadata"), dict) else {}
        spec = form.get("spec") if isinstance(form.get("spec"), dict) else {}
        return metadata, spec

    def replace_plan(k: catalog.Kind, namespace: str, name: str, metadata: dict[str, Any],
                     before: dict[str, Any], after: dict[str, Any], summary: str) -> dict[str, Any]:
        changes = diff(before, after)
        if not changes:
            raise SecureError(Code.INVALID_ARGUMENT, "The change would not modify the object.")
        body = {
            "metadata": {key: metadata[key] for key in ("name", "namespace", "labels", "annotations",
                                                         "description", "disable") if key in metadata},
            "spec": after,
        }
        body["metadata"].update({"name": name, "namespace": namespace})
        plan = rt.plans.create(identity=rt.identity().key, operation="replace", kind=k.name, namespace=namespace,
                               name=name, body=body, base_version=spec_hash(before), summary=summary)
        return _plan_result(plan, changes, rt.settings.plan_ttl_s)

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: attach or detach the WAF of a load balancer", idempotent=False)
    async def plan_set_lb_waf(
        namespace: Namespace,
        name: ObjectName,
        ctx: Context,
        app_firewall: Annotated[str | None, StringConstraints(max_length=63, pattern=XC_NAME),
                                Field(description="App Firewall to attach; omit to disable the WAF.")] = None,
        app_firewall_namespace: Annotated[str | None, StringConstraints(max_length=63, pattern=XC_NAME)] = None,
    ) -> dict:
        """Prepare attaching an App Firewall to an HTTP load balancer (or disabling its WAF).
        Returns a diff and a plan_id; nothing changes until apply_plan."""
        k = writable("http_loadbalancer", namespace)
        metadata, before = await current(k, namespace, name)
        after = copy.deepcopy(before)
        if app_firewall:
            set_oneof(k, after, "waf_choice", "app_firewall",
                      {"name": app_firewall, "namespace": app_firewall_namespace or namespace})
            summary = f"attach App Firewall {app_firewall} to {name}"
        else:
            set_oneof(k, after, "waf_choice", "disable_waf", {})
            summary = f"DISABLE the WAF of {name}"
        return replace_plan(k, namespace, name, metadata, before, after, summary)

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: WAF blocking or monitoring mode", idempotent=False)
    async def plan_set_waf_mode(
        namespace: Namespace, name: ObjectName, mode: Literal["blocking", "monitoring"], ctx: Context,
    ) -> dict:
        """Prepare switching an App Firewall between blocking and monitoring mode."""
        k = writable("app_firewall", namespace)
        metadata, before = await current(k, namespace, name)
        after = copy.deepcopy(before)
        set_oneof(k, after, "enforcement_mode_choice", mode, {})
        return replace_plan(k, namespace, name, metadata, before, after, f"set App Firewall {name} to {mode}")

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: add/remove IP prefixes", idempotent=False)
    async def plan_update_ip_prefix_set(
        namespace: Namespace,
        name: ObjectName,
        ctx: Context,
        add: Annotated[list[Prefix] | None, Field(max_length=200)] = None,
        remove: Annotated[list[Prefix] | None, Field(max_length=200)] = None,
        comment: Annotated[str | None, StringConstraints(max_length=100, pattern=r"^[A-Za-z0-9 _.,:\-]*$")] = None,
    ) -> dict:
        """Prepare adding/removing IPv4 prefixes in an ip_prefix_set (typically referenced by a service
        policy to block or allow clients). Prefixes are validated (e.g. 203.0.113.7/32)."""
        k = writable("ip_prefix_set", namespace)

        def normalize(values: list[str] | None) -> list[str]:
            out = []
            for value in values or []:
                try:
                    out.append(str(ipaddress.IPv4Network(value.strip(), strict=False)))
                except ValueError as exc:
                    raise SecureError(Code.INVALID_ARGUMENT, f"Invalid IPv4 prefix {value[:43]!r}.") from exc
            return out

        to_add, to_remove = normalize(add), set(normalize(remove))
        if not to_add and not to_remove:
            raise SecureError(Code.INVALID_ARGUMENT, "Nothing to add or remove.")
        metadata, before = await current(k, namespace, name)
        after = copy.deepcopy(before)
        entries = [e for e in after.get("ipv4_prefixes", []) if isinstance(e, dict)]
        entries = [e for e in entries if e.get("ipv4_prefix") not in to_remove]
        present = {e.get("ipv4_prefix") for e in entries}
        for prefix in to_add:
            if prefix not in present:
                entries.append({"ipv4_prefix": prefix, **({"description": comment} if comment else {})})
        after["ipv4_prefixes"] = entries
        return replace_plan(k, namespace, name, metadata, before, after,
                            f"ip_prefix_set {name}: +{len(to_add)} / -{len(to_remove)} prefixes")

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
        unknown = set(rule) - WAF_RULE_KEYS
        if "waf_skip_processing" in rule:
            raise SecureError(Code.INVALID_ARGUMENT, "Rules skipping all WAF processing are not allowed; "
                                                     "exclude specific signatures/violations instead.")
        if unknown:
            raise SecureError(Code.INVALID_ARGUMENT, f"Unexpected rule fields: {', '.join(sorted(unknown)[:10])}.")
        if "app_firewall_detection_control" not in rule:
            raise SecureError(Code.INVALID_ARGUMENT, "The rule needs app_firewall_detection_control.")
        meta = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
        if not isinstance(meta.get("name"), str) or not catalog.XC_NAME_RE.match(meta["name"]):
            raise SecureError(Code.INVALID_ARGUMENT, "rule.metadata.name must be a valid XC name.")
        if len(json.dumps(rule)) > 16_384:
            raise SecureError(Code.INVALID_ARGUMENT, "Rule too large.")
        metadata, before = await current(k, namespace, name)
        after = copy.deepcopy(before)
        exclusion = after.get("waf_exclusion") if isinstance(after.get("waf_exclusion"), dict) else {}
        if "waf_exclusion_policy" in exclusion:
            raise SecureError(Code.INVALID_ARGUMENT, "This load balancer uses a waf_exclusion_policy object: "
                                                     "modify that policy with plan_replace_object instead.")
        inline = exclusion.get("waf_exclusion_inline_rules")
        rules = list(inline.get("rules", [])) if isinstance(inline, dict) else []
        if any(isinstance(r, dict) and r.get("metadata", {}).get("name") == meta["name"] for r in rules):
            raise SecureError(Code.INVALID_ARGUMENT, "A rule with this name already exists.")
        rules.append(rule)
        after["waf_exclusion"] = {"waf_exclusion_inline_rules": {"rules": rules}}
        return replace_plan(k, namespace, name, metadata, before, after,
                            f"add WAF exclusion rule {meta['name']} to {name}")

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: replace the spec of an object", idempotent=False)
    async def plan_replace_object(
        kind: catalog.WritableKindName,
        namespace: Namespace,
        name: ObjectName,
        spec: Annotated[dict[str, Any], Field(description="Complete new spec (start from get_object view='spec').")],
        ctx: Context,
    ) -> dict:
        """Prepare replacing the whole spec of a writable object (load balancer, origin pool, App Firewall,
        service policy, rate limiter, API definition...). Top-level fields are checked against the API
        reference. Prefer the dedicated plan_* tools when they fit."""
        k = writable(kind, namespace)
        check_spec(k, spec)
        metadata, before = await current(k, namespace, name)
        return replace_plan(k, namespace, name, metadata, before, spec, f"replace spec of {kind} {name}")

    @rt.tool(mcp, ToolClass.WRITE, title="Plan: create an object", idempotent=False)
    async def plan_create_object(
        kind: catalog.WritableKindName,
        namespace: Namespace,
        name: ObjectName,
        spec: dict[str, Any],
        ctx: Context,
        description: Description = None,
        labels: Labels = None,
    ) -> dict:
        """Prepare creating a new object of a writable kind in an allow-listed namespace."""
        k = writable(kind, namespace)
        check_spec(k, spec)
        metadata: dict[str, Any] = {"name": name, "namespace": namespace}
        if description:
            metadata["description"] = description
        if labels:
            metadata["labels"] = labels
        plan = rt.plans.create(identity=rt.identity().key, operation="create", kind=k.name, namespace=namespace,
                               name=name, body={"metadata": metadata, "spec": spec}, base_version=None,
                               summary=f"create {kind} {name}")
        return _plan_result(plan, diff({}, spec), rt.settings.plan_ttl_s)

    @rt.tool(mcp, ToolClass.WRITE, title="Apply a planned change", idempotent=False)
    async def apply_plan(
        plan_id: Annotated[str, StringConstraints(min_length=10, max_length=64, pattern=r"^plan_[A-Za-z0-9_\-]+$")],
        ctx: Context,
    ) -> dict:
        """Apply a change prepared by a plan_* tool. A human must confirm it in the client
        (MCP elicitation); without an elicitation-capable client nothing is applied."""
        plan = rt.plans.take(plan_id, rt.identity().key)
        k = writable(plan.kind, plan.namespace)
        await _confirm(ctx, plan)
        if plan.operation == "replace":
            _, latest = await current(k, plan.namespace, plan.name)
            if spec_hash(latest) != plan.base_version:
                raise SecureError(Code.PLAN_STALE)
            path = catalog.kind_path(k, "replace", namespace=plan.namespace, name=plan.name)
            await rt.xc("PUT", path, body=plan.body)
        else:
            path = catalog.kind_path(k, "create", namespace=plan.namespace)
            await rt.xc("POST", path, body=plan.body)
        return sanitize.envelope("apply_plan", {"applied": True, "operation": plan.operation, "kind": plan.kind,
                                                "namespace": plan.namespace, "name": plan.name,
                                                "summary": plan.summary})


def _plan_result(plan: Plan, changes: list[dict[str, Any]], ttl: int) -> dict[str, Any]:
    return sanitize.envelope(
        "plan", {"plan_id": plan.plan_id, "operation": plan.operation, "kind": plan.kind,
                 "namespace": plan.namespace, "name": plan.name, "summary": plan.summary, "diff": changes},
        expires_in_s=ttl,
        next_step="Show the diff to the user, then call apply_plan(plan_id); the user will be asked to confirm.",
    )


async def _confirm(ctx: Context, plan: Plan) -> None:
    session = ctx.request_context.session
    params = getattr(session, "client_params", None)
    capabilities = getattr(params, "capabilities", None)
    if getattr(capabilities, "elicitation", None) is None:
        raise SecureError(Code.CONFIRMATION_REQUIRED, "This client does not support MCP elicitation.")
    result = await ctx.elicit(
        message=(f"Apply in F5 Distributed Cloud: {plan.summary} "
                 f"({plan.operation} {plan.kind} {plan.namespace}/{plan.name})? "
                 f"Type the object name '{plan.name}' to confirm."),
        schema=Confirmation,
    )
    data = getattr(result, "data", None)
    if (result.action != "accept" or not isinstance(data, Confirmation) or not data.approve
            or data.object_name.strip() != plan.name):
        raise SecureError(Code.CONFIRMATION_REQUIRED)
