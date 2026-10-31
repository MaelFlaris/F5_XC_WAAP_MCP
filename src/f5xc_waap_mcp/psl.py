"""Public Suffix List lookup (https://publicsuffix.org, MPL-2.0), vendored in
data/public_suffix_list.dat and refreshed with scripts/update_psl.py.

Used to flag WAF exclusions whose domain suffix is a public suffix ("gouv.fr",
"co.uk", "github.io"): such an exclusion covers sites of unrelated owners.
Both the ICANN and the private sections count. Rules follow the PSL algorithm:
"*.ck" makes every second-level name under ck a suffix, "!www.ck" is an
exception, and any single label is a suffix (implicit "*" rule).
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources


@lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    text = resources.files(__package__).joinpath("data/public_suffix_list.dat").read_text(encoding="utf-8")
    exact: set[str] = set()
    wildcard: set[str] = set()
    exceptions: set[str] = set()
    for line in text.splitlines():
        rule = line.strip().lower()
        if not rule or rule.startswith("//"):
            continue
        if rule.startswith("!"):
            exceptions.add(rule[1:])
        elif rule.startswith("*."):
            wildcard.add(rule[2:])
        else:
            exact.add(rule)
    return frozenset(exact), frozenset(wildcard), frozenset(exceptions)


def is_public_suffix(domain: str) -> bool:
    """True when ``domain`` itself is a public suffix (nothing registrable above it)."""
    name = domain.strip().strip(".").lower()
    if not name:
        return True
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return True  # unparsable: treat as broad
    exact, wildcard, exceptions = _rules()
    if name in exceptions:
        return False
    if "." not in name or name in exact:
        return True
    parent = name.split(".", 1)[1]
    return parent in wildcard
