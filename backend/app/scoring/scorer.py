from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Sequence

from ..admin_config import get_dimension_weights, get_provider_coefficients
from ..schemas import ProviderResult


def compute_category_scores(successful: Sequence[ProviderResult]) -> dict[str, int]:
    weights = get_dimension_weights()
    coefficients = get_provider_coefficients()
    category_data: dict[str, list[tuple[int, float]]] = defaultdict(list)

    for provider in successful:
        coefficient = coefficients.get(provider.provider, 1.0)
        effective_weight = coefficient * (provider.confidence / 100.0)

        for dimension, value in provider.dimensions.items():
            if dimension in weights:
                category_data[dimension].append((value, effective_weight))

    scores = {}
    for category, values in category_data.items():
        weighted_sum = sum(v * w for v, w in values)
        total_weight = sum(w for _, w in values)
        scores[category] = round(weighted_sum / total_weight) if total_weight > 0 else 0

    return scores


def compute_overall_score(score_breakdown: dict[str, int]) -> int:
    weights = get_dimension_weights()
    available_weight = sum(weights[dim] for dim in score_breakdown)
    if available_weight == 0:
        return 0

    weighted_total = sum(score_breakdown[dim] * weights[dim] for dim in score_breakdown)
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

    if score_breakdown.get("privacy", 0) >= 80:
        reasons.append("The page respects visitor privacy with minimal tracking.")
    elif "privacy" in score_breakdown:
        reasons.append("The page contains trackers or scripts that may compromise privacy.")

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
