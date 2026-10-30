# Test cases for .semgrep/rules.yml (semgrep --test .semgrep). Not imported anywhere.
import hashlib
import logging
import re
import sys

from pydantic_settings import SettingsConfigDict

TOKEN_RE = re.compile(r"^[A-Za-z0-9]{16,}$")


async def leaky_tool(token, audit, headers):
    value = token.get_secret_value()
    # ruleid: xc-token-leak
    audit.emit(token=value)
    # ruleid: xc-token-leak
    print(headers.get("x-f5xc-api-token"))
    # ruleid: xc-token-leak
    logging.info("token %s", value)
    # ok: xc-token-leak
    audit.emit(user=hashlib.sha256(value.encode()).hexdigest())
    # ruleid: xc-token-leak
    return value


def path_building(rt, catalog, k, name):
    # ok: xc-path-not-from-catalog
    rt.xc("GET", catalog.kind_path(k, "get", namespace="prod", name=name))
    # ruleid: xc-path-not-from-catalog
    rt.xc("GET", "/api/config/namespaces/prod/" + name)
    # ruleid: model-arg-in-fstring-url
    return f"/api/config/namespaces/{name}"


def validation(value):
    # ruleid: anchored-regex-match
    TOKEN_RE.match(value)
    # ok: anchored-regex-match
    TOKEN_RE.fullmatch(value)
    sys.stdout.flush()


# ruleid: settings-populate-by-name
BAD = SettingsConfigDict(env_file=None, populate_by_name=True)
# ok: settings-populate-by-name
GOOD = SettingsConfigDict(env_file=None, populate_by_name=False)
