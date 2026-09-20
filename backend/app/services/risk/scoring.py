from collections import defaultdict
from typing import Dict, List, Tuple
from app.services.risk.models import CategoryScoreBreakdown
from app.services.risk.thresholds import CATEGORY_WEIGHT_CAPS, MAX_TOTAL_SCORE, MIN_TOTAL_SCORE
from app.services.threat.models import ThreatCategory, ThreatIndicator


def deduplicate_indicators(indicators: List[ThreatIndicator]) -> List[ThreatIndicator]:
    """
    Deduplicates indicators by ID and preserves highest confidence and weight.
    """
    unique_map: Dict[str, ThreatIndicator] = {}
    for ind in indicators:
        if ind.id not in unique_map:
            unique_map[ind.id] = ind
        else:
            # If duplicate exists, keep highest weight/confidence
            existing = unique_map[ind.id]
            if ind.weight > existing.weight or ind.confidence > existing.confidence:
                unique_map[ind.id] = ind

    return list(unique_map.values())


def calculate_risk_score(
    indicators: List[ThreatIndicator]
) -> Tuple[int, List[CategoryScoreBreakdown], float]:
    """
    Calculates final normalized risk score (0-100), category score breakdowns, and confidence.
    Enforces category weight caps and deduplication.
    """
    deduped = deduplicate_indicators(indicators)

    # Group indicators by category
    category_groups = defaultdict(list)
    for ind in deduped:
        category_groups[ind.category].append(ind)

    breakdowns: List[CategoryScoreBreakdown] = []
    total_score = 0.0

    # Process each category
    for cat in ThreatCategory:
        items = category_groups[cat]
        raw_points = sum(item.weight for item in items)
        max_cap = CATEGORY_WEIGHT_CAPS.get(cat, 15.0)
        capped_points = min(raw_points, max_cap)
        total_score += capped_points

        breakdowns.append(
            CategoryScoreBreakdown(
                category=cat,
                raw_points=round(raw_points, 1),
                capped_points=round(capped_points, 1),
                max_cap=max_cap,
                indicator_count=len(items),
            )
        )

    # Final score clamped strictly between 0 and 100
    final_score = int(round(min(MAX_TOTAL_SCORE, max(MIN_TOTAL_SCORE, total_score))))

    # Calculate analysis confidence (0.0 to 1.0)
    if not deduped:
        confidence = 0.95
    else:
        # Weighted confidence based on indicator certainty
        conf_sum = sum(ind.confidence * ind.weight for ind in deduped)
        weight_sum = sum(ind.weight for ind in deduped)
        confidence = round(conf_sum / weight_sum if weight_sum > 0 else 0.90, 2)

    return final_score, breakdowns, confidence
