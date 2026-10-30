"""Exact reconstruction: replaying the rendered diff ops on `before` must give back
`after`. If two different changes could produce the same ops, the reviewer could
not tell them apart; this property rules that out (cf. finding F-14: "object
removed" and "object emptied" used to render identically)."""

import json
import re

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from f5xc_waap_mcp.errors import SecureError
from f5xc_waap_mcp.plans import diff, render

# No "name"/"metadata" keys: named list items are matched by name and covered by
# dedicated tests; here lists are positional so paths stay unambiguous.
KEYS = st.sampled_from(["a", "b", "c", "x y", "é", "k-1"])
SCALARS = st.one_of(st.none(), st.booleans(), st.integers(-3, 3), st.floats(allow_nan=False, width=16),
                    st.text(max_size=6))
JSONV = st.recursive(SCALARS, lambda inner: st.one_of(st.lists(inner, max_size=3),
                                                      st.dictionaries(KEYS, inner, max_size=3)), max_leaves=15)
TOKEN = re.compile(r'\.([A-Za-z0-9_\-]{1,80})|\.("(?:[^"\\]|\\.)*")|\[(\d+)\]')
GONE = object()


def parse(path: str) -> list:
    assert path.startswith("spec"), path
    rest, out = path[4:], []
    while rest:
        m = TOKEN.match(rest)
        assert m, f"unparsable path {path!r}"
        plain, quoted, index = m.groups()
        out.append(int(index) if index is not None else (json.loads(quoted) if quoted else plain))
        rest = rest[m.end():]
    return out


def setpath(root: dict, tokens: list, value) -> None:
    node = root
    for tok, nxt in zip(tokens, [*tokens[1:], None], strict=True):
        if nxt is None:
            if isinstance(tok, int) and tok == len(node):
                node.append(value)
            else:
                node[tok] = value
            return
        if isinstance(tok, int) and tok == len(node):
            node.append([] if isinstance(nxt, int) else {})
        elif not isinstance(tok, int) and tok not in node:
            node[tok] = [] if isinstance(nxt, int) else {}
        node = node[tok]


def cleanup(node):
    if isinstance(node, dict):
        return {k: cleanup(v) for k, v in node.items() if v is not GONE}
    if isinstance(node, list):
        return [cleanup(v) for v in node if v is not GONE]
    return node


def replay(before, ops):
    root = {"spec": json.loads(json.dumps(before))}
    for op in ops:
        tokens = ["spec", *parse(op["path"])]
        if op["op"] in ("add", "change"):
            setpath(root, tokens, json.loads(op["after"]))
        elif op["op"] == "remove":
            setpath(root, tokens, GONE)
        else:
            raise AssertionError(f"unexpected op {op}")
    return cleanup(root)["spec"]


@settings(max_examples=4000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(before=st.dictionaries(KEYS, JSONV, max_size=4), after=st.dictionaries(KEYS, JSONV, max_size=4))
def test_replaying_the_diff_reconstructs_after_exactly(before, after):
    try:
        ops = diff(before, after)
    except SecureError:
        return  # refused plans show nothing and apply nothing
    rebuilt = replay(before, ops)
    assert json.dumps(rebuilt, sort_keys=True) == json.dumps(after, sort_keys=True), render(ops)


def test_removed_and_emptied_object_render_differently():
    before = {"waf_exclusion": {"waf_exclusion_inline_rules": {"rules_x": 1}}}
    removed = render(diff(before, {}))
    emptied = render(diff(before, {"waf_exclusion": {"waf_exclusion_inline_rules": {}}}))
    assert removed != emptied
    assert "- spec.waf_exclusion (whole object removed)" in removed
