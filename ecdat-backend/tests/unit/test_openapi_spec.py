"""Unit tests for FastAPI OpenAPI schema generation and validation."""

from __future__ import annotations

import pytest

from ecdat.apps.api.main import create_app


class TestOpenAPISpec:
    def test_openapi_schema_generated_successfully(self) -> None:
        app = create_app()
        schema = app.openapi()

        assert schema is not None
        assert schema["openapi"].startswith("3.")
        assert schema["info"]["title"] == "ECDAT API"
        assert schema["info"]["version"] is not None

        # Verify key endpoints are defined
        paths = schema["paths"]
        assert "/api/v1/workspace/scans" in paths
        assert "/api/v1/workspace/assets" in paths
        assert "/api/v1/uploads" in paths
        assert "/api/v1/session" in paths
        assert "/health" in paths
        assert "/ready" in paths

    def test_schema_components_defined(self) -> None:
        app = create_app()
        schema = app.openapi()
        components = schema.get("components", {})
        schemas = components.get("schemas", {})
        assert len(schemas) > 0
