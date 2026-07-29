from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from ..schemas import ProviderResult

WEIGHTS = {
    "malware": 30,
    "reputation": 20,
    "age": 15,
    "infrastructure": 10,
    "https": 10,
    "blacklists": 10,
    "transparency": 5,
}


def compute_dimension_scores(provider_results: Iterable[ProviderResult]) -> dict[str, int]:
    score_buckets: dict[str, list[int]] = defaultdict(list)

    for provider in provider_results:
        for dimension, value in provider.dimensions.items():
            if dimension in WEIGHTS:
                score_buckets[dimension].append(value)

    return {
        dimension: round(sum(values) / len(values))
        for dimension, values in score_buckets.items()
    }


def compute_overall_score(score_breakdown: dict[str, int]) -> int:
    available_weight = sum(WEIGHTS[dim] for dim in score_breakdown)
    if available_weight == 0:
        return 0

    weighted_total = sum(score_breakdown[dim] * WEIGHTS[dim] for dim in score_breakdown)
    return round(weighted_total / available_weight)


def build_trust_reasons(provider_results: Iterable[ProviderResult], score_breakdown: dict[str, int]) -> list[str]:
    reasons: list[str] = []

    if not provider_results:
        return ["No providers were available for this analysis."]

    errors = [result.provider for result in provider_results if result.status != "success"]
    if errors:
        reasons.append("Some providers did not return full data.")

    if score_breakdown.get("https", 0) >= 80:
        reasons.append("The URL uses HTTPS.")
    elif "https" in score_breakdown:
        reasons.append("The URL is not secured by HTTPS.")

    if score_breakdown.get("age", 0) >= 80:
        reasons.append("The domain is mature and likely reliable.")
    elif "age" in score_breakdown:
        reasons.append("The domain is relatively new.")

    if len(provider_results) > 1:
        reasons.append(f"{len(provider_results)} sources were used for this analysis.")

    if not reasons:
        reasons.append("The analysis completed successfully.")

    return reasons
