from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

from ..config import APP_VERSION, PROVIDER_TIMEOUT_SECONDS
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
from ..scoring.scorer import (
    build_trust_reasons,
    compute_category_scores,
    compute_global_confidence,
    compute_overall_score,
)
from .cache import AnalysisCache


@dataclass
class AnalysisResult:
    response: AnalysisResponse
    processing_time_ms: int
    providers_count: int
    from_cache: bool
    algo_version: str


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
        self._cache = AnalysisCache()

    async def _run_provider(
        self, provider: Provider, url: str, api_key: str | None
    ) -> dict[str, Any]:
        """Run a single provider with a hard timeout, always returning a valid dict."""
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

    async def analyze(
        self,
        request: AnalyzeRequest,
        api_keys: dict[str, str] | None = None,
    ) -> AnalysisResult:
        normalized_url = str(request.url).rstrip("/")

        # Cache only when no user-specific API keys are provided —
        # different keys can yield different results for the same URL.
        use_cache = not api_keys
        if use_cache:
            entry = await self._cache.get(normalized_url)
            if entry is not None:
                return AnalysisResult(
                    response=entry.result,
                    processing_time_ms=0,
                    providers_count=entry.providers_count,
                    from_cache=True,
                    algo_version=entry.algo_version,
                )

        start = time.monotonic()

        tasks = [
            self._run_provider(
                provider,
                normalized_url,
                (api_keys or {}).get(getattr(provider, "api_key_name", None) or ""),
            )
            for provider in self.providers
        ]

        raw_results = await asyncio.gather(*tasks)

        provider_results = [
            ProviderResult(
                provider=r["provider"],
                status=r["status"],
                score=r["score"],
                confidence=r["confidence"],
                summary=r["summary"],
                details=r["details"],
                dimensions=r.get("dimensions", {}),
            )
            for r in raw_results
        ]

        successful = [pr for pr in provider_results if pr.status == "success"]
        score_breakdown = compute_category_scores(successful)
        overall_score = compute_overall_score(score_breakdown)
        average_confidence = compute_global_confidence(successful)
        reasons = build_trust_reasons(provider_results, score_breakdown, successful)

        processing_time_ms = round((time.monotonic() - start) * 1000)
        providers_count = len(self.providers)

        response = AnalysisResponse(
            url=normalized_url,
            overall_score=overall_score,
            confidence=average_confidence,
            reasons=reasons,
            score_breakdown=score_breakdown,
            results=provider_results,
        )

        if use_cache:
            await self._cache.set(
                normalized_url,
                response,
                providers_count=providers_count,
                algo_version=APP_VERSION,
            )

        return AnalysisResult(
            response=response,
            processing_time_ms=processing_time_ms,
            providers_count=providers_count,
            from_cache=False,
            algo_version=APP_VERSION,
        )