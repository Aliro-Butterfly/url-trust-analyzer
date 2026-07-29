from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from ..schemas import ProviderResult

WEIGHTS = {
    "malware": 30,
    "reputation": 20,
    "age": 15,
    "threat_intel": 15,
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


def build_trust_reasons(
    provider_results: list[ProviderResult],
    score_breakdown: dict[str, int],
    successful: list[ProviderResult] | None = None,
) -> list[str]:
    reasons: list[str] = []

    if not provider_results:
        return ["No providers were available for this analysis."]

    errors = [r.provider for r in provider_results if r.status == "error"]
    no_data = [r.provider for r in provider_results if r.status == "no_data"]
    if errors:
        reasons.append(f"Some providers encountered errors: {', '.join(errors)}.")
    if no_data:
        reasons.append(f"Some providers had no data available: {', '.join(no_data)}.")

    if successful is not None:
        reasons.append(f"{len(successful)}/{len(provider_results)} providers completed successfully.")

    if score_breakdown.get("https", 0) >= 80:
        reasons.append("The URL uses HTTPS.")
    elif "https" in score_breakdown:
        reasons.append("The URL is not secured by HTTPS.")

    if score_breakdown.get("age", 0) >= 80:
        reasons.append("The domain is mature and likely reliable.")
    elif "age" in score_breakdown:
        reasons.append("The domain is relatively new.")

    if score_breakdown.get("reputation", 0) >= 80:
        reasons.append("The URL has a good reputation signal.")
    elif "reputation" in score_breakdown:
        reasons.append("The URL has weak reputation signals.")

    if score_breakdown.get("malware", 0) < 60:
        reasons.append("Suspicious URL patterns were detected that lower the malware score.")

    if score_breakdown.get("blacklists", 0) < 70:
        reasons.append("The URL matches patterns commonly found in blocklist heuristics.")

    if score_breakdown.get("threat_intel", 0) < 60:
        reasons.append("External threat intelligence signals indicate risk or insufficient data.")

    if len(provider_results) > 1:
        reasons.append(f"{len(provider_results)} sources were used for this analysis.")

    if not reasons:
        reasons.append("The analysis completed successfully.")

    return reasons
