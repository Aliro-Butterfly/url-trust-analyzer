from ..providers.icann import IcannProvider
from ..schemas import AnalysisResponse, AnalyzeRequest, ProviderResult


class AnalyzerService:
    def __init__(self) -> None:
        self.providers = [IcannProvider()]

    async def analyze(self, request: AnalyzeRequest) -> AnalysisResponse:
        provider_results = []
        scores = []
        confidences = []
        normalized_url = str(request.url).rstrip("/")

        for provider in self.providers:
            result = await provider.analyze(normalized_url)
            provider_results.append(
                ProviderResult(
                    provider=result["provider"],
                    status=result["status"],
                    score=result["score"],
                    confidence=result["confidence"],
                    summary=result["summary"],
                    details=result["details"],
                )
            )
            scores.append(result["score"])
            confidences.append(result["confidence"])

        overall_score = round(sum(scores) / len(scores)) if scores else 0
        average_confidence = round(sum(confidences) / len(confidences)) if confidences else 0

        return AnalysisResponse(
            url=normalized_url,
            overall_score=overall_score,
            confidence=average_confidence,
            results=provider_results,
        )
