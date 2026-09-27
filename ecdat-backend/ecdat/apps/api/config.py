"""Application settings loaded from environment / .env file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All runtime configuration for the ECDAT backend.

    Values are loaded from environment variables (case-insensitive) and
    from a ``.env`` file in the working directory.
    """

    model_config = SettingsConfigDict(
        env_file=(Path(__file__).resolve().parents[3] / ".env", Path(__file__).resolve().parents[4] / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra='ignore',
    )

    # ------------------------------------------------------------------ #
    # Application                                                          #
    # ------------------------------------------------------------------ #
    app_name: str = "ECDAT Backend"
    app_version: str = "0.1.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = Field(False, validation_alias='ECDAT_DEBUG')
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # ------------------------------------------------------------------ #
    # Security                                                             #
    # ------------------------------------------------------------------ #
    session_cookie_secure: bool = False
    allowed_hosts: list[str] = ['localhost', '127.0.0.1', 'testserver', 'backend']

    # ------------------------------------------------------------------ #
    # Evidence / Storage                                                   #
    # ------------------------------------------------------------------ #
    evidence_store_path: str = Field(
        default="./evidence_store",
        description="Local filesystem path for scan evidence.",
    )

    # ------------------------------------------------------------------ #
    # CORS                                                                 #
    # ------------------------------------------------------------------ #
    cors_origins: list[str] = Field(
        default=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "http://127.0.0.1:3000", "http://localhost:8000", "http://127.0.0.1:8000"],
        description="Allowed CORS origins for the frontend.",
    )

    # ------------------------------------------------------------------ #
    # User Credentials from .env                                         #
    # ------------------------------------------------------------------ #
    auth_username: str | None = Field(default=None, validation_alias='AUTH_USERNAME')
    auth_password: str | None = Field(default=None, validation_alias='AUTH_PASSWORD')
    auth_users: str | None = Field(default=None, validation_alias='AUTH_USERS')


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached singleton Settings instance."""
    return Settings()
