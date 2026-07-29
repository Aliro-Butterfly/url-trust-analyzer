from pydantic import BaseModel, HttpUrl


class AnalyzeRequest(BaseModel):
    url: HttpUrl


class ProviderResult(BaseModel):
    provider: str
    status: str
    score: int
    confidence: int
    summary: str
    details: dict


class AnalysisResponse(BaseModel):
    url: str
    overall_score: int
    confidence: int
    reasons: list[str]
    results: list[ProviderResult]
