"""Targeted mutation testing of the security guards.

Each mutant disables ONE guard. A mutant the test suite does not kill is a guard
whose removal would go unnoticed in CI. Derived from the 2026-10-30 audit
(24/27 killed on a7b6436); guard strings updated and guards added since.

Two phases per mutant: the fast unit tests, then the Hypothesis property tests
only if the mutant survived the first phase.

Usage: python -I scripts/mutate_guards.py <repo_dir> <out_json>
Exit code 1 if any mutant survives.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROPERTY_TESTS = ["tests/test_audit_properties.py", "tests/test_diff_reconstruction.py"]

MUTANTS = [
    # --- from the audit (strings updated for fullmatch) ---
    ("catalog.py", "if not isinstance(value, str) or len(value) > 63 or not XC_NAME_RE.fullmatch(value):", "if False:", "path segment validation"),
    ("config.py", "if self.transport is Transport.STREAMABLE_HTTP and self.api_token is not None:", "if False:", "shared token refused in HTTP mode"),
    ("config.py", "return self.namespace_allowed(namespace) and namespace not in PROTECTED_NAMESPACES", "return self.namespace_allowed(namespace)", "protected namespaces"),
    ("guardrails.py", "if sess.total >= s.session_call_cap:", "if False:", "session call cap"),
    ("guardrails.py", "if len(user) >= s.rate_per_minute or len(self._global) >= s.global_rate_per_minute:", "if False:", "rate limits"),
    ("guardrails.py", "if repeats >= s.loop_threshold:", "if False:", "loop detection"),
    ("identity.py", 'if payload.get("disabled") is True or payload.get("state") in ("StateDisabled", "StateCreateFailed"):', "if False:", "disabled user refused"),
    ("identity.py", 'if user_type == "SERVICE" and not self._settings.allow_service_credentials:', "if False:", "service credentials refused"),
    ("plans.py", "if not secrets.compare_digest(plan.identity, identity):", "if False:", "plan bound to identity"),
    ("plans.py", "            del self._plans[plan_id]\n            return plan", "            return plan", "plan single use"),
    ("plans.py", 'if _SECRET_PATH.search(op["path"]):', "if False:", "secret fields refused in diff"),
    ("plans.py", "if len(render(differ.ops)) > MAX_RENDER_CHARS:", "if False:", "diff size limit"),
    ("runtime.py", "if not raw or not API_TOKEN_RE.fullmatch(raw.strip()):", "if not raw:", "token header format"),
    ("runtime.py", "if not self.settings.namespace_allowed(namespace):", "if False:", "namespace allow-list"),
    ("runtime.py", "if write and not self.settings.namespace_writable(namespace):", "if False:", "namespace writable check"),
    ("runtime.py", "return cls is ToolClass.READ or self.settings.writes_enabled", "return True", "write tools hidden in read mode"),
    ("sanitize.py", "if _SECRET_KEY.search(key_s):", "if False:", "secret redaction in read output"),
    ("xc_client.py", "if 300 <= status < 400:", "if False:", "redirects refused"),
    ("tools/changes.py", 'if "any_domain" in rule or not any(k in rule for k in ("exact_value", "suffix_value")):', "if False:", "WAF exclusion any-domain risk"),
    ("tools/changes.py", "if network.prefixlen < minimum:", "if False:", "minimum IP prefix length"),
    ("tools/changes.py", 'if outcome != "approved":', "if False:", "apply only when approved"),
    ("tools/changes.py", "if latest != plan.base_version:", "if False:", "stale plan refused"),
    ("tools/changes.py", 'if getattr(capabilities, "elicitation", None) is None:', "if False:", "client without elicitation"),
    ("tools/changes.py", "if data.object_name.strip() != plan.name:", "if False:", "typed object name"),
    ("tools/changes.py", "or data.hash_prefix.strip().lower() != plan.body_sha256[:8]):", "or False):", "HIGH RISK hash challenge"),
    ("tools/common.py", "if not _SAFE_VALUE.fullmatch(m.value):", "if False:", "log query value escaping"),
    ("tools/config_read.py", 'if view == "spec" and k.sensitive:', "if False:", "spec view refused on sensitive kinds"),
    # --- added after the audit ---
    ("config.py", "populate_by_name=False,", "populate_by_name=True,", "F-15 env read only by F5XC_* names"),
    ("config.py", "if parts.username or parts.password:", "if False:", "F-12 no credentials in proxy URL"),
    ("xc_client.py", "proxy=settings.https_proxy)", "proxy=None)", "F-12 proxy mounted on transport"),
    ("sanitize.py", "if unicodedata.category(ch) in _HIDDEN_CATEGORIES:", "if False:", "F-01 hidden Unicode categories"),
    ("sanitize.py", "        if depth > REF_DEPTH:\n            complete = False", "        if depth > REF_DEPTH:\n            pass", "F-03 deep spec marks scan incomplete"),
    ("plans.py", "_PLAIN_KEY.fullmatch(key)", "_PLAIN_KEY.match(key)", "F-13 diff key cannot end with newline"),
    ("plans.py", "elif type(before) is not type(after) or json.dumps(before) != json.dumps(after):", "elif before != after:", "F-06 scalar compare on serialised JSON"),
    ("plans.py", "if isinstance(value, dict | list) and value:", "if False:", "F-14 whole-object removal line"),
    # Not listed: _RELATIVE.fullmatch -> match in tools/common.py is an equivalent mutant
    # (the value is strip()-ed first, so no trailing newline can reach the regex).
    ("tools/changes.py", 'if isinstance(prefix, str) and prefix.strip("/") == "":', "if False:", "F-02 path prefix '/'"),
    ("tools/changes.py", "if len(labels) < 2 or (len(labels) == 2 and all(len(part) <= 3 for part in labels)):", "if False:", "F-02 TLD / public suffix"),
    ("tools/changes.py", "if isinstance(signatures, list) and len(signatures) > MAX_PRECISE_SIGNATURES:", "if False:", "F-02 mass signature exclusion"),
    ("tools/changes.py", "            if not scanned_all:\n                complete = False", "            if not scanned_all:\n                pass", "F-03 incomplete scan reported"),
    ("tools/changes.py", "if kill and os.path.exists(kill):", "if False:", "G kill switch"),
    ("tools/changes.py", "fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)", "fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)", "G rollback file is 0600"),
    ("identity.py", "            if exc.status == 401:", "            if exc.status in (401, 403):", "whoami 403 not negatively cached"),
]


def run_pytest(work: Path, args: list[str]) -> int:
    env = {"PYTHONPATH": str(work / "src"), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(work)}
    proc = subprocess.run([sys.executable, "-m", "pytest", "-o", "addopts=", "-q", "-x", "-p", "no:cacheprovider", *args],
                          cwd=work, env=env, capture_output=True, text=True, timeout=1800)
    return proc.returncode


def main(repo: Path, out: Path) -> int:
    results = []
    for file, old, new, guard in MUTANTS:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "repo"
            shutil.copytree(repo, work, ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv"))
            target = work / "src" / "f5xc_waap_mcp" / file
            code = target.read_text()
            if code.count(old) != 1:
                raise SystemExit(f"{file}: guard not found exactly once: {old!r}")
            target.write_text(code.replace(old, new))
            ignore = [arg for t in PROPERTY_TESTS for arg in ("--ignore", t)]
            killed = run_pytest(work, ["tests", *ignore]) != 0 or run_pytest(work, PROPERTY_TESTS) != 0
            results.append({"guard": guard, "file": file, "killed": killed})
            print(("KILLED  " if killed else "SURVIVED") + f"  {file:22} {guard}", flush=True)
    out.write_text(json.dumps(results, indent=2))
    survived = [r for r in results if not r["killed"]]
    print(f"\n{len(results) - len(survived)}/{len(results)} guards killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
