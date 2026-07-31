from __future__ import annotations

import asyncio
import os
from typing import Any

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
from ..providers.base import Provider
from ..schemas import AnalysisResponse, AnalyzeRequest, ProviderResult
from ..scoring.scorer import build_trust_reasons, compute_category_scores, compute_global_confidence, compute_overall_score

# Hard cap per individual provider. Prevents a single slow provider from
# blocking all others when they run concurrently via asyncio.gather.
PROVIDER_TIMEOUT_SECONDS = float(os.getenv("PROVIDER_TIMEOUT_SECONDS", "30"))


class AnalyzerService:
    def __init__(self) -> None:
        self.providers: list[Provider] = [
            IcannProvider(),
            UrlPropertiesProvider(),
            DnsProvider(),
            ReputationProvider(),
            VirusTotalProvider(),
            UrlVoidProvider(),
            SucuriProvider(),
            TalosProvider(),
            GoogleSafeBrowsingProvider(),
            ScamDocProvider(),
            URLScanProvider(),
            HackerTargetProvider(),
            AlienVaultOTXProvider(),
            AbuseIPDBProvider(),
            MozillaObservatoryProvider(),
            CertificateTransparencyProvider(),
            PrivacyProvider(),
        ]

    async def _run_provider(
        self, provider: Provider, url: str, api_key: str | None
    ) -> dict[str, Any]:
        """Run a single provider with a hard timeout, always returning a valid result dict."""
        try:
            return await asyncio.wait_for(
                provider.analyze(url, api_key),
                timeout=PROVIDER_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return {
                "provider": provider.name,
                "status": "error",
                "score": 50,
                "confidence": 0,
                "summary": f"{provider.name} timed out after {PROVIDER_TIMEOUT_SECONDS:.0f}s.",
                "details": {},
                "dimensions": {},
            }
        except Exception as exc:
            return {
                "provider": provider.name,
                "status": "error",
                "score": 50,
                "confidence": 0,
                "summary": f"Unexpected error: {exc}",
                "details": {},
                "dimensions": {},
            }

    async def analyze(self, request: AnalyzeRequest, api_keys: dict[str, str] | None = None) -> AnalysisResponse:
        normalized_url = str(request.url).rstrip("/")

        tasks = []
        for provider in self.providers:
            provider_api_key: str | None = None
            provider_api_name = getattr(provider, "api_key_name", None)
            if provider_api_name and api_keys:
                provider_api_key = api_keys.get(provider_api_name)
            tasks.append(self._run_provider(provider, normalized_url, provider_api_key))

        raw_results = await asyncio.gather(*tasks)

        provider_results = [
            ProviderResult(
                provider=result["provider"],
                status=result["status"],
                score=result["score"],
                confidence=result["confidence"],
                summary=result["summary"],
                details=result["details"],
                dimensions=result.get("dimensions", {}),
            )
            for result in raw_results
        ]

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