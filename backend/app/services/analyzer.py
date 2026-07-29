from ..providers import IcannProvider, UrlPropertiesProvider
from ..schemas import AnalysisResponse, AnalyzeRequest, ProviderResult


class AnalyzerService:
    def __init__(self) -> None:
        self.providers = [IcannProvider(), UrlPropertiesProvider()]

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
        reasons = self._build_reasons(provider_results)

        return AnalysisResponse(
            url=normalized_url,
            overall_score=overall_score,
            confidence=average_confidence,
            reasons=reasons,
            results=provider_results,
        )

    @staticmethod
    def _build_reasons(provider_results: list[ProviderResult]) -> list[str]:
        reasons: list[str] = []
        errors = [result.provider for result in provider_results if result.status != "success"]

        if errors:
            reasons.append("Some providers returned incomplete data.")

        https_provider = next((result for result in provider_results if result.provider == "URL Properties"), None)
        if https_provider:
            scheme = https_provider.details.get("scheme")
            if scheme != "https":
                reasons.append("The URL is not served over HTTPS.")
            else:
                reasons.append("The URL uses HTTPS.")

        if len(provider_results) > 1:
            reasons.append(f"{len(provider_results)} sources were used for this analysis.")

        if not reasons:
            reasons.append("The analysis completed successfully.")

        return reasons
