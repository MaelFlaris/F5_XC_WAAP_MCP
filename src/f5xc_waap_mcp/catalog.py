"""Closed catalogue of F5 XC endpoints, generated from the official API docs.

``data/catalog.json`` is produced by ``scripts/generate_catalog.py``. The
server can only call a path template present in this catalogue, and every
placeholder is filled with a value validated against the XC name rules. There
is no free-form request tool.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Literal

from .config import XC_NAME_RE
from .errors import Code, SecureError

_PLACEHOLDER = re.compile(r"\{([a-z_.]+)\}")


@dataclass(frozen=True)
class Kind:
    name: str
    doc: str
    family: str
    writable: bool
    sensitive: bool
    paths: dict[str, str]
    oneofs: dict[str, list[str]] = field(default_factory=dict)
    spec_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class DataEndpoint:
    id: str
    doc: str
    method: str
    path: str


def _load() -> tuple[dict[str, Kind], dict[str, DataEndpoint]]:
    raw = json.loads(resources.files(__package__).joinpath("data/catalog.json").read_text(encoding="utf-8"))
    kinds = {
        name: Kind(
            name=name,
            doc=item["doc"],
            family=item["family"],
            writable=item["writable"],
            sensitive=item["sensitive"],
            paths=item["paths"],
            oneofs=item["oneofs"],
            spec_fields=tuple(item["spec_fields"]),
        )
        for name, item in raw["kinds"].items()
    }
    data = {
        endpoint_id: DataEndpoint(endpoint_id, item["doc"], item["method"], item["path"])
        for endpoint_id, item in raw["data"].items()
    }
    return kinds, data


KINDS, DATA = _load()
KIND_NAMES: tuple[str, ...] = tuple(sorted(KINDS))

# Literal types used in tool signatures: the JSON schema shown to the model
# is a closed enum, and anything else is rejected before reaching our code.
KindName = Literal[KIND_NAMES]  # type: ignore[valid-type]


def kind(name: str) -> Kind:
    try:
        return KINDS[name]
    except KeyError as exc:
        raise SecureError(Code.INVALID_ARGUMENT, f"Unknown kind {name[:40]!r}.") from exc


def _segment(value: str) -> str:
    if not isinstance(value, str) or len(value) > 63 or not XC_NAME_RE.fullmatch(value):
        raise SecureError(Code.INVALID_ARGUMENT, "Names must match ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ (max 63).")
    return value


def render(template: str, params: dict[str, str]) -> str:
    """Fill a catalogue path template. Unknown or missing placeholders fail."""

    def substitute(match: re.Match[str]) -> str:
        key = match.group(1)
        lookup = key.removeprefix("metadata.")
        if lookup not in params:
            raise SecureError(Code.INTERNAL, detail=f"missing path parameter {key}")
        return _segment(params[lookup])

    path = _PLACEHOLDER.sub(substitute, template)
    if any(c in path for c in "?#%\\ ") or ".." in path:
        raise SecureError(Code.INVALID_ARGUMENT)
    return path


def kind_path(k: Kind, operation: str, **params: str) -> str:
    template = k.paths.get(operation)
    if template is None:
        raise SecureError(Code.INVALID_ARGUMENT, f"Operation {operation} is not available for {k.name}.")
    return render(template, params)


def data_path(endpoint_id: str, **params: str) -> tuple[str, str]:
    endpoint = DATA[endpoint_id]
    return endpoint.method, render(endpoint.path, params)


def describe() -> dict[str, Any]:
    """Catalogue overview returned by the ``list_supported_kinds`` tool."""
    families: dict[str, list[dict[str, Any]]] = {}
    for k in KINDS.values():
        families.setdefault(k.family, []).append(
            {"kind": k.name, "writable": k.writable, "sensitive": k.sensitive, "doc": k.doc}
        )
    return {family: sorted(items, key=lambda i: i["kind"]) for family, items in sorted(families.items())}
