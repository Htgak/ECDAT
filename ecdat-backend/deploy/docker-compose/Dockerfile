FROM python:3.11-slim

# System dependencies for Tree-sitter, psycopg, cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ git libpq-dev libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml .python-version README.md ./

# Install dependencies without installing project package yet
RUN uv sync --no-dev --no-install-project

# Copy application code
COPY ecdat/ ./ecdat/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY policies/ ./policies/

# Install the ecdat package
RUN uv sync --no-dev

ENV PYTHONPATH=/app
ENV UV_COMPILE_BYTECODE=1

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "ecdat.apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
