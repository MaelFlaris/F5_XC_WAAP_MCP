#!/usr/bin/env bash
# Regenerate the hash-pinned lock files.
#  * --exclude-newer: 14-day cooldown, releases younger than that are not picked up;
#  * --exclude-newer-package: explicit, commented exemptions for security fixes.
set -euo pipefail
cd "$(dirname "$0")/.."
CUTOFF="${CUTOFF:-$(date -u -d '14 days ago' +%Y-%m-%d)}"
EXEMPT=(
  --exclude-newer-package "certifi=2026-10-19"   # PYSEC-2026-4320 fix (2026.10.18)
  --exclude-newer-package "filelock=2026-10-18"  # CVE-2026-112941 fix (4.2.1), dev tooling only
)
COMMON=(--upgrade --generate-hashes --python-version 3.12 --universal --exclude-newer "$CUTOFF" "${EXEMPT[@]}" -q)
uv pip compile pyproject.toml "${COMMON[@]}" -o requirements.lock
uv pip compile pyproject.toml --extra dev "${COMMON[@]}" -o requirements-dev.lock
printf 'hatchling==1.27.0\n' | uv pip compile - "${COMMON[@]}" -o requirements-build.lock
echo "locks regenerated with cutoff $CUTOFF"
