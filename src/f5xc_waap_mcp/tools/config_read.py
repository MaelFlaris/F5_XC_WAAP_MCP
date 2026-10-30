"""Read tools for configuration objects (load balancers, WAF, policies...)."""

from typing import Annotated, Literal

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field, StringConstraints

from .. import catalog, sanitize
from ..errors import Code, SecureError
from ..runtime import Runtime, ToolClass
from .common import Namespace, ObjectName

LabelFilter = Annotated[
    str | None,
    StringConstraints(max_length=200, pattern=r"^[A-Za-z0-9_./\-=!,() ]*$"),
    Field(description="Optional XC label selector, e.g. 'env in (prod), team=web'."),
]


def register(mcp: FastMCP, rt: Runtime) -> None:
    @rt.tool(mcp, ToolClass.READ, title="List supported object kinds")
    async def list_supported_kinds(ctx: Context) -> dict:
        """List the F5 XC object kinds this server can read (and which ones it can modify),
        grouped by family: load_balancing, waf, policies, bot_and_users, api_security,
        network_security, dns, observability. Each entry links to the official API doc."""
        return sanitize.envelope(
            "list_supported_kinds", catalog.describe(), writes_enabled=rt.settings.writes_enabled,
            allowed_namespaces=list(rt.settings.allowed_namespaces),
        )

    @rt.tool(mcp, ToolClass.READ, title="List namespaces")
    async def list_namespaces(ctx: Context) -> dict:
        """List the namespaces of the tenant that are allow-listed on this server."""
        method, path = catalog.data_path("namespace.list")
        payload = await rt.xc(method, path)
        items = payload.get("items", []) if isinstance(payload, dict) else []
        names = sorted(
            sanitize.text(item.get("name"), 63) for item in items
            if isinstance(item, dict) and rt.settings.namespace_allowed(str(item.get("name")))
        )
        return sanitize.envelope("list_namespaces", names, count=len(names))

    @rt.tool(mcp, ToolClass.READ, title="List objects of a kind")
    async def list_objects(
        kind: catalog.KindName,
        namespace: Namespace,
        ctx: Context,
        label_filter: LabelFilter = None,
    ) -> dict:
        """List the objects of one kind in a namespace (name, description, labels, disabled flag).
        Use get_object for the configuration of one object."""
        rt.require_namespace(namespace)
        k = catalog.kind(kind)
        params = {"label_filter": label_filter} if label_filter else None
        payload = await rt.xc("GET", catalog.kind_path(k, "list", namespace=namespace), params=params)
        items = payload.get("items", []) if isinstance(payload, dict) else []
        if not isinstance(items, list):
            raise SecureError(Code.RESPONSE_INVALID)
        limit = rt.settings.max_items
        data = [sanitize.metadata(item) for item in items[:limit] if isinstance(item, dict)]
        return sanitize.envelope("list_objects", data, kind=kind, namespace=namespace, count=len(items),
                                 truncated=len(items) > limit, doc=k.doc)

    @rt.tool(mcp, ToolClass.READ, title="Get one object")
    async def get_object(
        kind: catalog.KindName,
        namespace: Namespace,
        name: ObjectName,
        ctx: Context,
        view: Annotated[
            Literal["summary", "spec", "referrers"],
            Field(description="summary: which option of each documented choice group is configured and "
                              "which objects are referenced; spec: the full configuration with secrets "
                              "redacted; referrers: the objects that reference this one."),
        ] = "summary",
    ) -> dict:
        """Read one configuration object (e.g. an http_loadbalancer, app_firewall, service_policy)."""
        rt.require_namespace(namespace)
        k = catalog.kind(kind)
        if view == "spec" and k.sensitive:
            raise SecureError(Code.SENSITIVE_KIND)
        params = {"response_format": "GET_RSP_FORMAT_REFERRING_OBJECTS"} if view == "referrers" else None
        obj = await rt.xc("GET", catalog.kind_path(k, "get", namespace=namespace, name=name), params=params)
        if not isinstance(obj, dict):
            raise SecureError(Code.RESPONSE_INVALID)
        if view == "summary":
            data = sanitize.summarize(k, obj)
        elif view == "spec":
            data = sanitize.full_spec(obj)
        else:
            referring = obj.get("referring_objects") if isinstance(obj.get("referring_objects"), list) else []
            data = {
                **sanitize.metadata(obj),
                "referring_objects": [
                    {"kind": sanitize.text(r.get("kind"), 63), **(sanitize.ref(r) or {})}
                    for r in referring[:100] if isinstance(r, dict)
                ],
            }
        return sanitize.envelope("get_object", data, kind=kind, namespace=namespace, view=view, doc=k.doc)

    @rt.tool(mcp, ToolClass.READ, title="Active namespace service policies")
    async def get_active_service_policies(namespace: Namespace, ctx: Context) -> dict:
        """Service policies applied at namespace level (used by load balancers configured with
        'service_policies_from_namespace')."""
        rt.require_namespace(namespace)
        method, path = catalog.data_path("namespace.active_service_policies", namespace=namespace)
        payload = await rt.xc(method, path)
        policies = payload.get("service_policies", []) if isinstance(payload, dict) else []
        data = [r for r in (sanitize.ref(p) for p in policies[:100]) if r]
        return sanitize.envelope("get_active_service_policies", data, namespace=namespace)
