FROM python:3.11-slim

# =============================================================================
# Layer 1 — OS dependencies
# =============================================================================
# Tree-sitter, psycopg, cryptography, and Java JDK for JADX / Ghidra
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ git libssl-dev libffi-dev curl unzip wget \
    default-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/default-java
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# =============================================================================
# Layer 2 — Decompiler tools
# =============================================================================
# JADX 1.5.1 — APK / DEX / JAR → Java source
ARG INSTALL_DECOMPILERS=false
ARG JADX_SHA256
ARG GHIDRA_SHA256
ARG JADX_VERSION=1.5.1
RUN if [ "$INSTALL_DECOMPILERS" = "true" ]; then test -n "$JADX_SHA256" && mkdir -p /opt/tools/jadx && \
    wget -q -O /tmp/jadx.zip \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" && \
    echo "$JADX_SHA256  /tmp/jadx.zip" | sha256sum -c - && \
    unzip -q /tmp/jadx.zip -d /opt/tools/jadx && \
    rm /tmp/jadx.zip && \
    chmod +x /opt/tools/jadx/bin/jadx; fi

ENV PATH="/opt/tools/jadx/bin:${PATH}"

# Ghidra 11.1.2 — ELF / PE (EXE/DLL) / Mach-O → symbol/function analysis
ARG GHIDRA_VERSION=11.1.2
ARG GHIDRA_DATE=20240709
RUN if [ "$INSTALL_DECOMPILERS" = "true" ]; then test -n "$GHIDRA_SHA256" && mkdir -p /opt/tools/ghidra && \
    wget -q -O /tmp/ghidra.zip \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
    echo "$GHIDRA_SHA256  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt/tools/ghidra && \
    rm /tmp/ghidra.zip && \
    chmod +x /opt/tools/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC/support/analyzeHeadless; fi

ENV PATH="/opt/tools/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC/support:${PATH}"

# =============================================================================
# Layer 3 — Python application
# =============================================================================
# Install uv from official astral image
COPY --from=ghcr.io/astral-sh/uv:0.10.9@sha256:10902f58a1606787602f303954cea099626a4adb02acbac4c69920fe9d278f82 /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency specifications first for optimal layer caching
COPY pyproject.toml uv.lock .python-version README.md ./

# Install project dependencies without building the project package yet
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source code
COPY ecdat/ ./ecdat/

# Build and install the ecdat-backend package
RUN uv sync --frozen --no-dev

ARG ECDAT_GIT_COMMIT=unknown
ENV ECDAT_GIT_COMMIT=${ECDAT_GIT_COMMIT}
ENV PYTHONPATH=/app
ENV UV_COMPILE_BYTECODE=1
ENV PYTHONUNBUFFERED=1
# Standalone deployments do not inherit docker-compose.yml environment values.
# Point both SQLite auth and scan storage at the directory owned by UID 10001.
ENV EVIDENCE_STORE_PATH=/evidence_store

RUN groupadd --gid 10001 ecdat && useradd --uid 10001 --gid 10001 --create-home ecdat && \
    mkdir -p /evidence_store && chown 10001:10001 /evidence_store && chmod 700 /evidence_store
ENV UV_NO_SYNC=1
USER 10001:10001
EXPOSE 8000

# Default command starts FastAPI via uvicorn
CMD ["/app/.venv/bin/uvicorn", "ecdat.apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
