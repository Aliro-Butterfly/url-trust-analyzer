from typing import Any

from pydantic import BaseModel, Field, HttpUrl


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
