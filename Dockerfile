# syntax=docker/dockerfile:1
# f5xc-waap-mcp: non-root, read-only friendly, hash-verified dependencies.
# Base image pinned by digest (python:3.12-slim-trixie). Trixie instead of bookworm:
# 164 vs 271 OS vulnerabilities, 0 vs 2 critical (Trivy 0.76.1, 2026-10-30).
ARG BASE=python:3.12-slim-trixie@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

FROM ${BASE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY requirements.lock requirements-build.lock ./
# Build tooling in its own venv; the runtime venv has no pip at all and is populated
# by the build venv's pip. Every artifact is checked against the lock hashes.
RUN python -m venv /opt/build \
 && /opt/build/bin/pip install --require-hashes -r requirements-build.lock \
 && python -m venv --without-pip /opt/venv \
 && /opt/build/bin/pip --python /opt/venv/bin/python install --require-hashes -r requirements.lock
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN /opt/build/bin/pip wheel --no-deps --no-build-isolation -w /wheels . \
 && /opt/build/bin/pip --python /opt/venv/bin/python install --no-deps /wheels/*.whl

FROM ${BASE}
LABEL org.opencontainers.image.title="f5xc-waap-mcp" \
      org.opencontainers.image.description="Security-by-design MCP server for F5 Distributed Cloud WAAP" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /opt/venv /opt/venv
# pip is not needed at runtime: drop the base image's copy (6 known CVEs in pip 25.0.1).
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 /usr/local/lib/python3.12/ensurepip
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    F5XC_MCP_TRANSPORT=streamable-http
# No shell tooling is needed at runtime; run as an unprivileged numeric user.
USER 65532:65532
EXPOSE 8765
ENTRYPOINT ["f5xc-waap-mcp"]
