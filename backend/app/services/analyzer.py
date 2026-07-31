from ..providers import (
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
    CertificateTransparencyProvider,
    DnsProvider,
    GoogleSafeBrowsingProvider,
    HackerTargetProvider,
    IcannProvider,
    MozillaObservatoryProvider,
    PrivacyProvider,
    ReputationProvider,
    ScamDocProvider,
    SucuriProvider,
    TalosProvider,
    URLScanProvider,
    UrlPropertiesProvider,
    UrlVoidProvider,
    VirusTotalProvider,
)
from ..schemas import AnalysisResponse, AnalyzeRequest, ProviderResult
from ..scoring.scorer import build_trust_reasons, compute_category_scores, compute_global_confidence, compute_overall_score


class AnalyzerService:
    def __init__(self) -> None:
        self.providers = [
            IcannProvider(),
            UrlPropertiesProvider(),
            DnsProvider(),
            ReputationProvider(),
            VirusTotalProvider(),
            UrlVoidProvider(),
            SucuriProvider(),
            GoogleSafeBrowsingProvider(),
            ScamDocProvider(),
            URLScanProvider(),
            TalosProvider(),
            HackerTargetProvider(),
            AlienVaultOTXProvider(),
            AbuseIPDBProvider(),
            MozillaObservatoryProvider(),
            CertificateTransparencyProvider(),
            PrivacyProvider(),
        ]

    async def analyze(self, request: AnalyzeRequest, api_keys: dict[str, str] | None = None) -> AnalysisResponse:
        provider_results = []
        normalized_url = str(request.url).rstrip("/")

        for provider in self.providers:
            provider_api_key = None
            provider_api_name = getattr(provider, "api_key_name", None)
            if provider_api_name and api_keys:
                provider_api_key = api_keys.get(provider_api_name)

            try:
                result = await provider.analyze(normalized_url, provider_api_key)
            except TypeError:
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

        successful = [pr for pr in provider_results if pr.status == "success"]
        score_breakdown = compute_category_scores(successful)
        overall_score = compute_overall_score(score_breakdown)
        average_confidence = compute_global_confidence(successful)
        reasons = build_trust_reasons(provider_results, score_breakdown, successful)

        return AnalysisResponse(
            url=normalized_url,
            overall_score=overall_score,
            confidence=average_confidence,
            reasons=reasons,
            score_breakdown=score_breakdown,
            results=provider_results,
        )
