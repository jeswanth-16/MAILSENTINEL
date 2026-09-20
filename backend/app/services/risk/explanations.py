from typing import List
from app.services.risk.models import ExplanationItem, RecommendationItem
from app.services.threat.models import (
    ThreatCategory,
    ThreatClassification,
    ThreatIndicator,
    ThreatSeverityLevel,
)


def generate_explanations(
    indicators: List[ThreatIndicator],
) -> List[ExplanationItem]:
    """
    Generates structured, human-understandable explanations for each detected indicator.
    Sorted by highest score contribution.
    """
    # Sort indicators by highest weight
    sorted_indicators = sorted(indicators, key=lambda x: (x.weight, x.confidence), reverse=True)

    explanations: List[ExplanationItem] = []
    for ind in sorted_indicators:
        explanations.append(
            ExplanationItem(
                indicator_id=ind.id,
                category=ind.category,
                title=ind.name,
                evidence=ind.evidence,
                score_contribution=ind.weight,
                confidence=ind.confidence,
                rationale=ind.description,
            )
        )

    return explanations


def generate_executive_summary(
    score: int,
    severity: ThreatSeverityLevel,
    classification: ThreatClassification,
    indicators: List[ThreatIndicator],
) -> str:
    """
    Generates a concise, evidence-grounded executive summary of the threat assessment.
    """
    if severity == ThreatSeverityLevel.CLEAN or score < 25:
        return "Email exhibits standard RFC 5322 compliance with passing authentication and no observable threat indicators."

    high_indicators = [i.name for i in indicators if i.severity in (ThreatSeverityLevel.CRITICAL, ThreatSeverityLevel.HIGH)]
    ind_summary = f"Key triggers include {', '.join(high_indicators[:3])}." if high_indicators else "Multiple low-severity anomalies detected."

    return (
        f"Assessed as {severity.value} risk ({score}/100) and classified as {classification.value}. "
        f"{ind_summary} System determined high probability of targeted malicious intent."
    )


def generate_recommendations(
    classification: ThreatClassification,
    indicators: List[ThreatIndicator],
) -> List[RecommendationItem]:
    """
    Generates actionable, defensive cybersecurity recommendations based on detected indicators.
    """
    recs: List[RecommendationItem] = []
    indicator_ids = {i.id for i in indicators}

    # 1. Credential harvesting / Phishing guidance
    if (
        classification in (ThreatClassification.CREDENTIAL_HARVESTING, ThreatClassification.PHISHING)
        or any(i.category == ThreatCategory.URL for i in indicators)
    ):
        recs.append(
            RecommendationItem(
                priority="HIGH",
                action="Block Extracted Domains & Do Not Follow Links",
                guidance="Instruct recipient not to enter credentials or access embedded URLs. Add extracted domains to perimeter DNS sinkhole.",
            )
        )

    # 2. Wire fraud / Financial pressure guidance
    if (
        classification in (ThreatClassification.BUSINESS_EMAIL_COMPROMISE, ThreatClassification.FINANCIAL_FRAUD)
        or "SOCENG_FINANCIAL_PRESSURE" in indicator_ids
    ):
        recs.append(
            RecommendationItem(
                priority="HIGH",
                action="Out-of-Band Payment Verification Required",
                guidance="Never authorize funds, invoice revisions, or payroll changes based solely on email instructions. Verify via known out-of-band phone number.",
            )
        )

    # 3. Attachment guidance
    if (
        classification == ThreatClassification.MALICIOUS_ATTACHMENT
        or any(i.category == ThreatCategory.ATTACHMENT for i in indicators)
    ):
        recs.append(
            RecommendationItem(
                priority="HIGH",
                action="Quarantine Attachment & Prevent Execution",
                guidance="Do not download or open attachment payload on production workstations. Submit SHA-256 hash to enterprise SIEM/EDR blocklist.",
            )
        )

    # 4. Authentication / Mail routing guidance
    if any(i.category == ThreatCategory.AUTHENTICATION for i in indicators):
        recs.append(
            RecommendationItem(
                priority="MEDIUM",
                action="Review Inbound Mail Gateway Policies",
                guidance="Ensure DMARC quarantine or reject policy is strictly enforced on inbound relays for spoofed external domains.",
            )
        )

    # 5. Baseline monitoring if low risk
    if not recs:
        recs.append(
            RecommendationItem(
                priority="LOW",
                action="Standard Monitoring",
                guidance="No immediate containment action required. Message complies with standard security baselines.",
            )
        )

    return recs
