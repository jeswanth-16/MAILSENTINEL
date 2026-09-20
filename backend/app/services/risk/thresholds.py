from typing import Dict
from app.services.threat.models import ThreatCategory, ThreatSeverityLevel

# Score to Severity Mapping Thresholds
SEVERITY_THRESHOLDS = [
    (75, 100, ThreatSeverityLevel.CRITICAL),
    (50, 74, ThreatSeverityLevel.HIGH),
    (25, 49, ThreatSeverityLevel.MEDIUM),
    (0, 24, ThreatSeverityLevel.LOW),
]

# Maximum point contribution caps per category to prevent unbounded score inflation
CATEGORY_WEIGHT_CAPS: Dict[ThreatCategory, float] = {
    ThreatCategory.AUTHENTICATION: 20.0,
    ThreatCategory.SENDER: 15.0,
    ThreatCategory.URL: 20.0,
    ThreatCategory.DOMAIN: 15.0,
    ThreatCategory.SOCIAL_ENGINEERING: 15.0,
    ThreatCategory.ATTACHMENT: 10.0,
    ThreatCategory.HEADER_ROUTE: 5.0,
    ThreatCategory.CORRELATION: 15.0,
}

MAX_TOTAL_SCORE = 100.0
MIN_TOTAL_SCORE = 0.0


def map_score_to_severity(score: int) -> ThreatSeverityLevel:
    """
    Maps an integer score (0 - 100) to a standardized ThreatSeverityLevel.
    """
    if score <= 0:
        return ThreatSeverityLevel.CLEAN

    for min_score, max_score, severity in SEVERITY_THRESHOLDS:
        if min_score <= score <= max_score:
            return severity

    return ThreatSeverityLevel.LOW
