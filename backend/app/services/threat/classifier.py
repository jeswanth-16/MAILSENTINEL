from typing import List
from app.services.threat.models import ThreatClassification, ThreatIndicator


def classify_threat(
    indicators: List[ThreatIndicator],
    total_risk_score: int
) -> ThreatClassification:
    """
    Evidence-based threat classification based on detected indicators and score thresholds.
    """
    if not indicators or total_risk_score < 25:
        return ThreatClassification.BENIGN

    indicator_ids = {ind.id for ind in indicators}

    # 1. Malicious / Dangerous Attachment Priority
    if (
        "ATTACH_DOUBLE_EXTENSION" in indicator_ids
        or "ATTACH_SCRIPT_OR_EXECUTABLE" in indicator_ids
        or "ATTACH_MACRO_ENABLED" in indicator_ids
    ):
        return ThreatClassification.MALICIOUS_ATTACHMENT

    # 2. Business Email Compromise (BEC) Priority
    # Look for authority title spoofing + financial request or reply-to redirection
    if (
        "SENDER_AUTHORITY_IMPERSONATION" in indicator_ids
        and ("SOCENG_FINANCIAL_PRESSURE" in indicator_ids or "SENDER_REPLY_TO_MISMATCH" in indicator_ids)
    ):
        return ThreatClassification.BUSINESS_EMAIL_COMPROMISE

    # 3. Financial Fraud / Wire Scams
    if (
        "SOCENG_FINANCIAL_PRESSURE" in indicator_ids
        and ("AUTH_SPF_FAIL" in indicator_ids or "SENDER_REPLY_TO_MISMATCH" in indicator_ids or "DOMAIN_LOOKALIKE_BRAND" in indicator_ids)
    ):
        return ThreatClassification.FINANCIAL_FRAUD

    # 4. Credential Harvesting Priority
    if (
        "SOCENG_CREDENTIAL_HARVESTING" in indicator_ids
        or "URL_CREDENTIAL_PHISH_PATH" in indicator_ids
    ):
        return ThreatClassification.CREDENTIAL_HARVESTING

    # 5. Phishing (Lookalike domains, typosquatting, homoglyphs with auth failures)
    if (
        "DOMAIN_LOOKALIKE_BRAND" in indicator_ids
        or "DOMAIN_PUNYCODE_HOMOGLYPH" in indicator_ids
        or "URL_IP_BASED_HOST" in indicator_ids
    ):
        return ThreatClassification.PHISHING

    # 6. Impersonation
    if (
        "SENDER_AUTHORITY_IMPERSONATION" in indicator_ids
        or "SENDER_RETURN_PATH_MISMATCH" in indicator_ids
    ):
        return ThreatClassification.IMPERSONATION

    # 7. Fallback based on score
    if total_risk_score >= 50:
        return ThreatClassification.PHISHING
    elif total_risk_score >= 25:
        return ThreatClassification.SUSPICIOUS

    return ThreatClassification.BENIGN
