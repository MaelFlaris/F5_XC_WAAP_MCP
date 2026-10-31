"""Refresh src/f5xc_waap_mcp/data/public_suffix_list.dat from publicsuffix.org.

Checks the MPL header and both section markers before replacing the file, then
prints its VERSION line and SHA-256 for the commit message.
Usage: python scripts/update_psl.py
"""

import hashlib
import pathlib
import sys
import urllib.request

URL = "https://publicsuffix.org/list/public_suffix_list.dat"
OUT = pathlib.Path(__file__).resolve().parents[1] / "src" / "f5xc_waap_mcp" / "data" / "public_suffix_list.dat"


def main() -> int:
    with urllib.request.urlopen(URL, timeout=60) as resp:  # fixed https URL
        data = resp.read()
    text = data.decode("utf-8")
    required = ("Mozilla Public", "===BEGIN ICANN DOMAINS===", "===BEGIN PRIVATE DOMAINS===", "\ngouv.fr\n")
    if any(marker not in text for marker in required) or len(data) < 100_000:
        raise SystemExit("unexpected content, file not replaced")
    OUT.write_bytes(data)
    version = next((line for line in text.splitlines() if line.startswith("// VERSION:")), "?")
    print(version, hashlib.sha256(data).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
