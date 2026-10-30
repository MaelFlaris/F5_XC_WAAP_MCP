"""atheris fuzzing of the parsers that see untrusted input (from the 2026-10-30 audit).

Invariants (any violation raises -> crash report):
  * build_query: output is {field<op>"value"} with no quote, brace, backslash or newline
    in the value (the audit version tolerated a trailing newline: finding F-05);
  * catalog.render: no traversal, query, fragment, encoding or newline in the path;
  * sanitize.text: single line, bounded, no hidden character (categories Cc/Cf/Co/Cn/Cs);
  * project_record: never raises, keys only from the allow-list;
  * diff/render: exactly one rendered line per op (keys cannot forge lines, F-13);
  * find_references_to: never raises;
  * parse_time: only SecureError on bad input.
Usage: python -I fuzz/fuzz_parsers.py -max_total_time=60
"""

import json
import sys
import unicodedata

import atheris

with atheris.instrument_imports():
    from f5xc_waap_mcp import catalog, sanitize
    from f5xc_waap_mcp.errors import SecureError
    from f5xc_waap_mcp.plans import diff, render
    from f5xc_waap_mcp.tools.common import EventMatcher, build_query, parse_time


def one(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 6)
    s = fdp.ConsumeUnicodeNoSurrogates(200)
    if choice == 0:
        try:
            q = build_query([EventMatcher(field="vh_name", op="=~", value=s)])
        except (SecureError, ValueError):
            return
        inner = q[len('{vh_name=~"'):-2]
        assert q.startswith('{vh_name=~"') and q.endswith('"}'), q
        assert not any(c in inner for c in '"{}\\\n\r'), q
    elif choice == 1:
        try:
            path = catalog.render("/api/config/namespaces/{namespace}/http_loadbalancers/{name}",
                                  {"namespace": "prod", "name": s})
        except SecureError:
            return
        assert path.count("/") == 6 and ".." not in path and not set("?#%\\ \n\r") & set(path), path
    elif choice == 2:
        out = sanitize.text(s, 50)
        assert len(out) <= 50 and "\n" not in out and "\r" not in out, repr(out)
        assert not any(unicodedata.category(c) in ("Cc", "Cf", "Co", "Cn", "Cs") for c in out), repr(out)
    elif choice == 3:
        rec = sanitize.project_record(s, sanitize.EVENT_FIELDS)
        assert set(rec) <= set(sanitize.EVENT_FIELDS) | {"unparsed", "_dropped_fields"}, rec
    elif choice == 4:
        try:
            before = json.loads(s)
            after = json.loads(fdp.ConsumeUnicodeNoSurrogates(200))
        except (ValueError, RecursionError):
            return
        try:
            ops = diff({"x": before}, {"x": after})
        except SecureError:
            return
        except RecursionError:
            raise AssertionError("diff recursion on deep JSON") from None
        assert not ops or len(render(ops).split("\n")) == len(ops)
    elif choice == 5:
        try:
            spec = json.loads(s)
        except (ValueError, RecursionError):
            return
        sanitize.find_references_to(spec, "target", "prod")
    else:
        try:
            parse_time(s)
        except SecureError:
            return
        except OverflowError as exc:
            raise AssertionError(f"parse_time overflow on {s!r}") from exc


if __name__ == "__main__":
    atheris.Setup(sys.argv, one)
    atheris.Fuzz()
