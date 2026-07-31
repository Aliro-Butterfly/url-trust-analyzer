"""Application exception hierarchy.

All domain errors extend AppError. FastAPI exception handlers in main.py
convert them to consistent JSON — no raw Python exceptions ever reach the client.
"""
from __future__ import annotations


class AppError(Exception):
    """Root of all application errors."""
    status_code: int = 500
    code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, *, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: list[str] = details or []


class ValidationError(AppError):
    status_code = 422
    code = "VALIDATION_ERROR"


class AuthenticationError(AppError):
    status_code = 401
    code = "AUTHENTICATION_ERROR"


class AuthorizationError(AppError):
    status_code = 403
    code = "AUTHORIZATION_ERROR"


class ProviderTimeout(AppError):
    status_code = 504
    code = "PROVIDER_TIMEOUT"


class ProviderUnavailable(AppError):
    status_code = 502
    code = "PROVIDER_UNAVAILABLE"


class DatabaseError(AppError):
    status_code = 503
    code = "DATABASE_ERROR"


class CacheError(AppError):
    status_code = 503
    code = "CACHE_ERROR"


class RateLimitExceeded(AppError):
    status_code = 429
    code = "RATE_LIMIT_EXCEEDED"


class InternalError(AppError):
    status_code = 500
    code = "INTERNAL_ERROR"