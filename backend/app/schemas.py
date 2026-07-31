from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field, HttpUrl, constr

from .config import APP_VERSION

T = TypeVar("T")


# ── Request schemas ────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: HttpUrl


class UserCreate(BaseModel):
    username: constr(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9._-]+$")
    password: constr(min_length=8)


class LoginRequest(BaseModel):
    username: str
    password: str


class ApiKeysUpdate(BaseModel):
    urlscan: str | None = None
    google_safebrowsing: str | None = None
    virustotal: str | None = None
    abuseipdb: str | None = None


# ── Response schemas ───────────────────────────────────────────────────────────

class ProviderResult(BaseModel):
    provider: str
    status: str
    score: int
    confidence: int
    summary: str
    details: dict
    dimensions: dict[str, int] = Field(default_factory=dict)


class AnalysisResponse(BaseModel):
    url: str
    overall_score: int
    confidence: int
    reasons: list[str]
    score_breakdown: dict[str, int]
    results: list[ProviderResult]


class HistoryItem(BaseModel):
    id: int
    url: str
    overall_score: int
    confidence: int
    created_at: str
    processing_time_ms: int | None = None
    providers_count: int | None = None
    algo_version: str | None = None
    from_cache: bool = False
    report: dict[str, Any]


class AuthResponse(BaseModel):
    username: str
    is_admin: bool = False


class ApiKeysStatus(BaseModel):
    has_urlscan: bool
    has_google_safebrowsing: bool
    has_virustotal: bool
    has_abuseipdb: bool


# ── Homogeneous API envelope ──────────────────────────────────────────────────

class ResponseMetadata(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = APP_VERSION
    processingTime: int | None = None   # milliseconds
    providerCount: int | None = None
    cached: bool | None = None


class ApiResponse(BaseModel, Generic[T]):
    """
    Standard response envelope for all API endpoints.

    Every response carries:
    - success:   whether the operation completed without error
    - message:   human-readable status description
    - data:      the typed payload (None on error)
    - errors:    list of error strings (empty on success)
    - metadata:  timestamp, version, and optional analysis metadata
    """
    success: bool = True
    message: str = ""
    data: T | None = None
    errors: list[str] = Field(default_factory=list)
    metadata: ResponseMetadata = Field(default_factory=ResponseMetadata)

    @classmethod
    def ok(
        cls,
        data: T,
        message: str = "",
        *,
        processing_time_ms: int | None = None,
        provider_count: int | None = None,
        cached: bool | None = None,
    ) -> "ApiResponse[T]":
        return cls(
            success=True,
            message=message,
            data=data,
            errors=[],
            metadata=ResponseMetadata(
                processingTime=processing_time_ms,
                providerCount=provider_count,
                cached=cached,
            ),
        )

    @classmethod
    def error(cls, message: str, errors: list[str] | None = None, *, code: str = "ERROR") -> "ApiResponse[None]":
        return cls(
            success=False,
            message=message,
            data=None,
            errors=errors or [message],
            metadata=ResponseMetadata(),
        )