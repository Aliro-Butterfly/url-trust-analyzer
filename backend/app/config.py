"""Centralized application configuration.

Every environment variable and path constant is defined here.
Other modules MUST import from this file instead of calling os.getenv() directly.
"""
from __future__ import annotations

import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BACKEND_DIR: Path = Path(__file__).resolve().parent.parent
LOG_FILE: Path = BACKEND_DIR / "backend_api.log"
ADMIN_CONFIG_PATH: Path = BACKEND_DIR / "admin_config.json"
DB_DEFAULT_PATH: Path = BACKEND_DIR / "analysis_history.db"

# ── Application ───────────────────────────────────────────────────────────────
APP_VERSION: str = "0.1.0"
APP_NAME: str = "URL Trust Analyzer"

# ── Auth ──────────────────────────────────────────────────────────────────────
_jwt_secret = os.getenv("JWT_SECRET")
if not _jwt_secret:
    raise RuntimeError(
        "JWT_SECRET environment variable is required. "
        "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )
JWT_SECRET: str = _jwt_secret
JWT_ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
ADMIN_TOKEN_EXPIRE_SECONDS: int = int(os.getenv("ADMIN_TOKEN_EXPIRE_SECONDS", "3600"))
AUTH_COOKIE_NAME: str = "auth_token"
ADMIN_COOKIE_NAME: str = "admin_token"
COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "").strip().lower() in {"1", "true", "yes", "on"}

# ── Admin ─────────────────────────────────────────────────────────────────────
ADMIN_USERNAME: str | None = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD: str | None = os.getenv("ADMIN_PASSWORD")

# ── Crypto ────────────────────────────────────────────────────────────────────
_api_keys_secret = os.getenv("API_KEYS_SECRET") or os.getenv("JWT_SECRET")
if not _api_keys_secret:
    raise RuntimeError(
        "API_KEYS_SECRET or JWT_SECRET environment variable is required "
        "to encrypt stored API keys."
    )
API_KEYS_SECRET: str = _api_keys_secret

# ── Database ──────────────────────────────────────────────────────────────────
# NOTE: DB_PATH is intentionally a function so tests can override it via
# monkeypatch.setenv("URL_TRUST_ANALYZER_DB", ...) at runtime.
def get_db_path() -> str:
    return os.getenv("URL_TRUST_ANALYZER_DB") or str(DB_DEFAULT_PATH)

DB_BUSY_TIMEOUT_MS: int = int(os.getenv("DB_BUSY_TIMEOUT_MS", "5000"))

# ── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_AUTH_MAX: int = int(os.getenv("RATE_LIMIT_AUTH_MAX", "20"))
RATE_LIMIT_AUTH_WINDOW: int = int(os.getenv("RATE_LIMIT_AUTH_WINDOW", "60"))
RATE_LIMIT_ADMIN_MAX: int = int(os.getenv("RATE_LIMIT_ADMIN_MAX", "10"))
RATE_LIMIT_ADMIN_WINDOW: int = int(os.getenv("RATE_LIMIT_ADMIN_WINDOW", "60"))

# ── Analysis ──────────────────────────────────────────────────────────────────
PROVIDER_TIMEOUT_SECONDS: float = float(os.getenv("PROVIDER_TIMEOUT_SECONDS", "30"))
ANALYSIS_CACHE_TTL_SECONDS: float = float(os.getenv("ANALYSIS_CACHE_TTL_SECONDS", "300"))
ANALYSIS_CACHE_MAX_SIZE: int = int(os.getenv("ANALYSIS_CACHE_MAX_SIZE", "200"))

# ── History / pagination ──────────────────────────────────────────────────────
HISTORY_DEFAULT_LIMIT: int = int(os.getenv("HISTORY_DEFAULT_LIMIT", "20"))
HISTORY_MAX_LIMIT: int = int(os.getenv("HISTORY_MAX_LIMIT", "100"))

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "WARNING").upper()