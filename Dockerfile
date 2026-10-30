# syntax=docker/dockerfile:1
# f5xc-waap-mcp: non-root, read-only friendly, hash-verified dependencies.
# Base image pinned by digest (python:3.12-slim-bookworm).
ARG BASE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337

FROM ${BASE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY requirements.lock requirements-build.lock ./
# Runtime dependencies: every artifact checked against the lock hashes.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes -r requirements.lock
# Build backend in a separate venv, so it does not end up in the runtime image.
RUN python -m venv /opt/build \
 && /opt/build/bin/pip install --require-hashes -r requirements-build.lock
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN /opt/build/bin/pip wheel --no-deps --no-build-isolation -w /wheels . \
 && /opt/venv/bin/pip install --no-deps /wheels/*.whl

FROM ${BASE}
LABEL org.opencontainers.image.title="f5xc-waap-mcp" \
      org.opencontainers.image.description="Security-by-design MCP server for F5 Distributed Cloud WAAP" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    F5XC_MCP_TRANSPORT=streamable-http
# No shell tooling is needed at runtime; run as an unprivileged numeric user.
USER 65532:65532
EXPOSE 8765
ENTRYPOINT ["f5xc-waap-mcp"]
