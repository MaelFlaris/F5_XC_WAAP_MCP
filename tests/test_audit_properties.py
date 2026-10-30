"""Audit property tests, imported verbatim from the external audit of 2026-10-30
(audit_tests/test_audit_properties.py). Before the fixes 12 of them failed
(F-01, F-02, F-03, F-06); they must all pass.
"""
# ruff: noqa

import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from f5xc_waap_mcp import sanitize
from f5xc_waap_mcp.errors import Code, SecureError
from f5xc_waap_mcp.plans import diff, render
from f5xc_waap_mcp.tools import changes
from f5xc_waap_mcp.tools.common import EventMatcher, build_query

# --- strategies ---------------------------------------------------------------
KEYS = st.sampled_from(["a", "b", "rules", "name", "spec_x", "k-1", "path", "x y", "é", "a\nb"])
SCALARS = st.one_of(st.none(), st.booleans(), st.integers(-3, 3), st.text(max_size=8))
JSONV = st.recursive(
    SCALARS,
    lambda inner: st.one_of(st.lists(inner, max_size=4), st.dictionaries(KEYS, inner, max_size=4)),
    max_leaves=20,
)


def _leaves(node, path=()):
    if isinstance(node, dict) and node:
        for k, v in node.items():
            yield from _leaves(v, (*path, k))
    elif isinstance(node, list) and node:
        for i, v in enumerate(node):
            yield from _leaves(v, (*path, i))
    else:
        yield path, node


def _same_json(a, b) -> bool:
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# --- P1: a change is never invisible -----------------------------------------
@settings(max_examples=3000, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(before=JSONV, after=JSONV)
def test_P1_any_json_difference_yields_ops_or_refusal(before, after):
    """If the JSON sent to XC differs, the reviewer must see at least one op (or the plan is refused)."""
    try:
        ops = diff({"s": before}, {"s": after})
    except SecureError as exc:
        assert exc.code in (Code.DIFF_TOO_LARGE, Code.SECRET_FIELD)
        return
    if not _same_json(before, after):
        assert ops, f"invisible change: {before!r} -> {after!r}"


# --- P2: every new scalar value is printed in the confirmation text ----------
@settings(max_examples=3000, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(before=st.dictionaries(KEYS, JSONV, max_size=4), after=st.dictionaries(KEYS, JSONV, max_size=4))
def test_P2_every_new_leaf_value_appears_in_render(before, after):
    try:
        text = render(diff(before, after))
    except SecureError:
        return
    old = {json.dumps(v, sort_keys=True) for _, v in _leaves(before)}
    for path, value in _leaves(after):
        if not path or isinstance(value, bool) or value in ({}, []):  # containers shown via child ops; bool/int is P4
            continue
        shown = json.dumps(value, sort_keys=True, ensure_ascii=True)
        if json.dumps(value, sort_keys=True) not in old:
            assert shown in text, f"value {shown} not shown"


# --- P3: rendered diff has exactly one line per op (no forged lines) ---------
@settings(max_examples=2000, deadline=None)
@given(key=st.text(min_size=1, max_size=30), value=st.text(max_size=60))
def test_P3_keys_and_values_cannot_forge_lines(key, value):
    try:
        ops = diff({}, {key: value})
    except SecureError:
        return
    assert len(render(ops).split("\n")) == len(ops)


# --- P4: concrete counter-examples -------------------------------------------
@pytest.mark.parametrize(("before", "after"), [(1, True), (0, False), (True, 1.0)])
def test_P4_bool_int_swap_is_visible(before, after):
    """JSON true != 1 for XC (a bool flag vs a number). Python == says they are equal."""
    ops = diff({"x": before}, {"x": after})
    assert ops, "change true<->1 is not shown to the reviewer"


# --- P5: invisible characters never reach the model ---------------------------
INVISIBLE = {
    "tag chars (ASCII smuggling)": "".join(chr(0xE0000 + ord(c)) for c in "ignore previous"),
    "variation selector": "a️b",
    "soft hyphen": "a­b",
    "arabic letter mark": "a؜b",
    "bidi override": "a‮b",
    "zero width": "a​b",
}


@pytest.mark.parametrize("name", list(INVISIBLE))
def test_P5_invisible_chars_stripped_from_untrusted_text(name):
    out = sanitize.text("UA:" + INVISIBLE[name])
    assert all(ch.isprintable() and ord(ch) < 0xE0000 for ch in out), f"{name} survives: {out!r}"


def test_P5b_tag_smuggling_survives_event_projection():
    payload = "Mozilla/5.0" + INVISIBLE["tag chars (ASCII smuggling)"]
    rec = sanitize.project_record(json.dumps({"user_agent": payload}), sanitize.EVENT_FIELDS)
    assert rec["user_agent"] == "Mozilla/5.0", f"hidden payload kept: {rec['user_agent']!r}"


# --- P6: reference scan must not silently stop at 50 references --------------
def test_P6_collect_refs_reports_truncation():
    spec = {"routes": [{"pool": {"name": f"p{i}", "namespace": "prod"}} for i in range(60)]}
    spec["routes"].append({"policy": {"name": "new-object", "namespace": "prod"}})
    refs = sanitize.collect_refs(spec)
    assert any(r["name"] == "new-object" for r in refs), (
        f"{len(refs)} refs returned, the 61st (new-object) is missing and nothing says the list is truncated"
    )


# --- P7: WAF exclusion breadth -------------------------------------------------
def _rule(**kw):
    base = {"metadata": {"name": "r1"}, "exact_value": "shop.example.com", "path_prefix": "/api/cart",
            "app_firewall_detection_control": {"exclude_signature_contexts": [
                {"signature_id": 200001234, "context": "CONTEXT_PARAMETER"}]}}
    base.update(kw)
    return base


def test_P7a_precise_rule_is_standard():
    assert changes.exclusion_rule_risks(_rule()) == []


@pytest.mark.parametrize(("label", "rule"), [
    ("path_prefix '/' covers the whole site", _rule(path_prefix="/")),
    ("domain suffix of one label", _rule(exact_value=None, suffix_value="com")),
    ("200 signatures at once", _rule(app_firewall_detection_control={"exclude_signature_contexts": [
        {"signature_id": 200000000 + i, "context": "CONTEXT_ANY"} for i in range(200)]})),
])
def test_P7b_broad_rules_should_be_high_risk(label, rule):
    rule = {k: v for k, v in rule.items() if v is not None}
    assert changes.exclusion_rule_risks(rule), f"not flagged: {label}"


# --- P8: log query injection ----------------------------------------------------
@settings(max_examples=3000, deadline=None)
@given(value=st.text(min_size=1, max_size=60))
def test_P8_matcher_value_cannot_break_out(value):
    try:
        q = build_query([EventMatcher(field="vh_name", op="=", value=value)])
    except (SecureError, ValueError):
        return
    inner = q[len('{vh_name="'):-2]
    assert q.startswith('{vh_name="') and q.endswith('"}') and '"' not in inner and "{" not in inner
