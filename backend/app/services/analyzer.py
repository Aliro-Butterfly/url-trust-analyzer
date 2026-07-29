from ..providers import DnsProvider, IcannProvider, ReputationProvider, UrlPropertiesProvider
from ..schemas import AnalysisResponse, AnalyzeRequest, ProviderResult
from ..scoring.scorer import build_trust_reasons, compute_dimension_scores, compute_overall_score


class AnalyzerService:
    def __init__(self) -> None:
        self.providers = [IcannProvider(), UrlPropertiesProvider(), DnsProvider(), ReputationProvider()]

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
                    dimensions=result.get("dimensions", {}),
                )
            )
            scores.append(result["score"])
            confidences.append(result["confidence"])

        score_breakdown = compute_dimension_scores(provider_results)
        overall_score = compute_overall_score(score_breakdown)
        average_confidence = round(sum(confidences) / len(confidences)) if confidences else 0
        reasons = build_trust_reasons(provider_results, score_breakdown)

        return AnalysisResponse(
            url=normalized_url,
            overall_score=overall_score,
            confidence=average_confidence,
            reasons=reasons,
            score_breakdown=score_breakdown,
            results=provider_results,
        )
