#!/usr/bin/env bash
# Regenerate the hash-pinned lock files.
#  * --exclude-newer: 14-day cooldown, releases younger than that are not picked up;
#  * --exclude-newer-package: explicit, commented exemptions for security fixes; remove each
#    one once its date is older than the cutoff (it is then a no-op).
set -euo pipefail
cd "$(dirname "$0")/.."
LATEST="$(date -u -d '14 days ago' +%Y-%m-%d)"
CUTOFF="${CUTOFF:-$LATEST}"
# An override may only move the cutoff further back, never inside the 14-day cooldown.
if ! [[ "$CUTOFF" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || ! date -u -d "$CUTOFF" >/dev/null 2>&1 \
   || [[ "$CUTOFF" > "$LATEST" ]]; then
  echo "CUTOFF must be a date (YYYY-MM-DD) no later than $LATEST" >&2
  exit 1
fi
EXEMPT=(
  --exclude-newer-package "certifi=2026-10-19"   # PYSEC-2026-4320 fix (2026.10.18)
  --exclude-newer-package "filelock=2026-10-18"  # CVE-2026-112941 fix (4.2.1), dev tooling only
)
COMMON=(--upgrade --generate-hashes --python-version 3.12 --universal --exclude-newer "$CUTOFF" "${EXEMPT[@]}" -q)
uv pip compile pyproject.toml "${COMMON[@]}" -o requirements.lock
uv pip compile pyproject.toml --extra dev "${COMMON[@]}" -o requirements-dev.lock
uv pip compile pyproject.toml --extra fuzz "${COMMON[@]}" -o requirements-fuzz.lock
# semgrep runs in its own venv (it pins its own mcp version): standalone lock.
printf 'semgrep==1.180.0\n' | uv pip compile - "${COMMON[@]}" -o requirements-sast.lock
printf 'hatchling==1.27.0\n' | uv pip compile - "${COMMON[@]}" -o requirements-build.lock
echo "locks regenerated with cutoff $CUTOFF"
