from typing import Any

from pydantic import BaseModel, Field, HttpUrl, constr


class AnalyzeRequest(BaseModel):
    url: HttpUrl


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
    report: dict[str, Any]


class UserCreate(BaseModel):
    username: constr(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9._-]+$")
    password: constr(min_length=8)


class AuthResponse(BaseModel):
    username: str
    is_admin: bool = False


class ApiKeysUpdate(BaseModel):
    urlscan: str | None = None
    google_safebrowsing: str | None = None
    virustotal: str | None = None
    abuseipdb: str | None = None


class ApiKeysStatus(BaseModel):
    has_urlscan: bool
    has_google_safebrowsing: bool
    has_virustotal: bool
    has_abuseipdb: bool
