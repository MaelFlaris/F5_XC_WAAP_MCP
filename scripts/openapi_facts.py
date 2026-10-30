"""Extract, from the raw OpenAPI documents published on docs.cloud.f5.com, the facts
the server's security relies on, with the SHA-256 of each page as provenance.

Facts checked:
  * replace (PUT) of writable kinds: parameters, request body fields, whether any
    version precondition exists (resource_version, If-Match, etag) anywhere in the spec;
  * metadata fields accepted by replace (what the PUT rewrites);
  * GET response_format values (FOR_REPLACE, REFERRING_OBJECTS, BROKEN_REFERENCES);
  * policySimpleWafExclusionRule / policyAppFirewallDetectionControl fields and oneofs;
  * whoami (user CustomAPI.Get) path and response fields.

Usage: python scripts/openapi_facts.py [--cache DIR] > docs/evidence/openapi-facts.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from generate_catalog import NEXT_DATA, fetch, find_spec

KINDS = {"http_loadbalancer": "views-http-loadbalancer", "app_firewall": "app-firewall",
         "ip_prefix_set": "ip-prefix-set", "service_policy": "service-policy",
         "waf_exclusion_policy": "waf-exclusion-policy", "origin_pool": "views-origin-pool"}
VERSION_WORDS = re.compile(r"(?i)\bresource_version\b|\bif-match\b|\betag\b|\bversion\b")


def load(slug: str, cache: pathlib.Path | None) -> tuple[dict, str]:
    html = fetch(slug, cache)
    spec = find_spec(json.loads(NEXT_DATA.search(html).group(1)))
    return spec, hashlib.sha256(html.encode()).hexdigest()


def ref(defs: dict, schema: dict) -> dict:
    return defs[schema["$ref"].split("/")[-1]]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", type=pathlib.Path, default=None)
    args = parser.parse_args()
    facts: dict = {"source": "https://docs.cloud.f5.com/docs-v2/api", "kinds": {}}
    for kind, slug in KINDS.items():
        spec, digest = load(slug, args.cache)
        defs = spec["definitions"]
        put = next((p, o["put"]) for p, o in spec["paths"].items() if "put" in o)
        body = next(p for p in put[1]["parameters"] if p["in"] == "body")
        request = ref(defs, body["schema"])
        meta = ref(defs, request["properties"]["metadata"])
        get_op = next(o["get"] for p, o in spec["paths"].items()
                      if "get" in o and o["get"].get("operationId", "").endswith("API.Get"))
        formats = next((p.get("enum") for p in get_op["parameters"] if p["name"] == "response_format"), None)
        # Where a precondition would have to be: PUT parameters (headers, query) and the
        # replace body / metadata schemas. (A whole-document search hits unrelated text,
        # e.g. "disable_on_etag_header" in the LB compression options.)
        scope = json.dumps([put[1]["parameters"], request, meta])
        facts["kinds"][kind] = {
            "page_sha256": digest,
            "replace_path": put[0],
            "replace_parameters": [(p["name"], p["in"]) for p in put[1]["parameters"]],
            "replace_body_fields": sorted(request["properties"]),
            "replace_metadata_fields": sorted(meta["properties"]),
            "version_precondition_in_put": sorted({m.group(0).lower() for m in VERSION_WORDS.finditer(scope)}),
            "get_response_formats": formats,
        }
    spec, digest = load("app-security", args.cache)
    defs = spec["definitions"]
    rule = defs["policySimpleWafExclusionRule"]
    facts["waf_exclusion"] = {
        "page_sha256": digest,
        "simple_rule_fields": sorted(rule["properties"]),
        "simple_rule_oneofs": {k[len("x-ves-oneof-field-"):]: json.loads(v)
                               for k, v in rule.items() if k.startswith("x-ves-oneof-field-")},
        "detection_control_fields": sorted(defs["policyAppFirewallDetectionControl"]["properties"]),
    }
    spec, digest = load("user", args.cache)
    defs = spec["definitions"]
    path = "/api/web/custom/namespaces/{namespace}/whoami"
    op = spec["paths"][path]["get"]
    response = ref(defs, op["responses"]["200"]["schema"])
    facts["whoami"] = {
        "page_sha256": digest, "path": path, "operation": op.get("operationId"),
        "description": op.get("description", "").strip()[:200],
        "response_fields_used": {f: f in response["properties"] for f in ("name", "email", "user_uuid", "type",
                                                                          "state", "disabled")},
        "user_type_enum": defs.get("userUserType", {}).get("enum"),
    }
    json.dump(facts, sys.stdout, indent=1, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
