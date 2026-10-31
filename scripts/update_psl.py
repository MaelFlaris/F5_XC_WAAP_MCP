"""Refresh src/f5xc_waap_mcp/data/public_suffix_list.dat from publicsuffix.org.

Checks the MPL header, both section markers, a set of canary rules and that the
number of rules did not drop by more than 2 % before replacing the file
(atomically), then prints its VERSION line and SHA-256 for the commit message.
Usage: python scripts/update_psl.py
"""

import hashlib
import os
import pathlib
import sys
import urllib.request

URL = "https://publicsuffix.org/list/public_suffix_list.dat"
OUT = pathlib.Path(__file__).resolve().parents[1] / "src" / "f5xc_waap_mcp" / "data" / "public_suffix_list.dat"


# Rules from both sections that must always be present (a truncated list would silently
# drop the "public suffix" warning of the WAF exclusion risk check).
CANARIES = frozenset({"com", "fr", "gouv.fr", "co.uk", "com.au", "*.ck", "!www.ck", "github.io", "blogspot.com"})


def rules(text: str) -> set[str]:
    return {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("//")}


def main() -> int:
    with urllib.request.urlopen(URL, timeout=60) as resp:  # fixed https URL
        data = resp.read()
    text = data.decode("utf-8")
    required = ("Mozilla Public", "===BEGIN ICANN DOMAINS===", "===BEGIN PRIVATE DOMAINS===")
    if any(marker not in text for marker in required) or len(data) < 100_000:
        raise SystemExit("unexpected content, file not replaced")
    new_rules = rules(text)
    missing = CANARIES - new_rules
    if missing:
        raise SystemExit(f"canary rules missing ({', '.join(sorted(missing))}), file not replaced")
    old_rules = rules(OUT.read_text(encoding="utf-8")) if OUT.exists() else set()
    if len(new_rules) < len(old_rules) * 0.98:
        raise SystemExit(f"rule count dropped from {len(old_rules)} to {len(new_rules)}, file not replaced")
    tmp = OUT.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, OUT)
    version = next((line for line in text.splitlines() if line.startswith("// VERSION:")), "?")
    print(version, hashlib.sha256(data).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
