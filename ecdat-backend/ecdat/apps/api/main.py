"""FastAPI application factory for ECDAT backend."""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ecdat.apps.api.config import get_settings
from ecdat.apps.api.access import guard, router as access_router, RequestSizeLimit
from ecdat.apps.api.routers import (
    advisories,
    uploads,
    workspace,
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown hooks."""
    settings = get_settings()
    from ecdat.apps.api.auth.store import sync_env_users
    sync_env_users()
    uploads.recover_interrupted()
    logger.info(
        "ecdat_api_starting",
        version=settings.app_version,
        environment=settings.environment,
    )
    yield
    logger.info("ecdat_api_stopping")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="ECDAT API",
        description=(
            "Enterprise Cryptographic Discovery & Analysis Tool — REST API. "
            "All capabilities are accessible via this API."
        ),
        version=settings.app_version,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------ #
    # Middleware                                                           #
    # ------------------------------------------------------------------ #
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.middleware('http')(guard)
    app.add_middleware(RequestSizeLimit)
    hosts = list(dict.fromkeys(settings.allowed_hosts + ['testserver']))
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    # ------------------------------------------------------------------ #
    # Routers                                                              #
    # ------------------------------------------------------------------ #
    api_prefix = "/api/v1"

    app.include_router(access_router, prefix=api_prefix, tags=["Session"])
    app.include_router(advisories.router, prefix=api_prefix, tags=["Advisories"])
    app.include_router(uploads.router, prefix=api_prefix, tags=["File scans"])
    app.include_router(workspace.router, prefix=api_prefix, tags=['Workspace'])

    # ------------------------------------------------------------------ #
    # Health and readiness checks                                          #
    # ------------------------------------------------------------------ #
    @app.get("/health", tags=["Health"])
    @app.get(f"{api_prefix}/health", tags=["Health"])
    async def health() -> dict:
        return {
            "status": "ok",
            "version": settings.app_version,
        }

    @app.get("/ready", tags=["Health"])
    @app.get(f"{api_prefix}/ready", tags=["Health"])
    def ready():
        import tempfile
        from fastapi.responses import JSONResponse
        try:
            with tempfile.TemporaryFile(dir=uploads.storage_root()) as probe:
                probe.write(b'readiness')
                probe.flush()
        except OSError:
            return JSONResponse({'status': 'not_ready', 'storage': 'unavailable'}, status_code=503)
        return {"status": "ready", "version": settings.app_version, 'storage': 'writable'}

    return app



app = create_app()
