import asyncio
import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.email import analyze_email_bytes
from app.services.risk import (
    CATEGORY_WEIGHT_CAPS,
    assess_email_threat,
    calculate_risk_score,
    deduplicate_indicators,
    map_score_to_severity,
)
from app.services.threat.classifier import classify_threat
from app.services.threat.indicators import (
    detect_all_indicators,
    detect_attachment_indicators,
    detect_authentication_indicators,
    detect_sender_indicators,
    detect_social_engineering_indicators,
    detect_url_and_domain_indicators,
)
from app.services.threat.models import (
    ThreatCategory,
    ThreatClassification,
    ThreatIndicator,
    ThreatSeverityLevel,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(filename: str) -> bytes:
    filepath = os.path.join(FIXTURES_DIR, filename)
    with open(filepath, "rb") as f:
        return f.read()


def test_phishing_eml_threat_assessment():
    """
    Tests that sample_phishing.eml produces a high/critical threat score with multiple evidence indicators.
    """
    file_bytes = read_fixture("sample_phishing.eml")
    forensic = analyze_email_bytes(file_bytes, original_filename="sample_phishing.eml")

    assessment = asyncio.run(assess_email_threat(forensic))

    # 1. Verification of high/critical risk score and severity
    assert assessment.risk_score >= 70
    assert assessment.severity in (ThreatSeverityLevel.CRITICAL, ThreatSeverityLevel.HIGH)
    assert assessment.confidence >= 0.85
    assert assessment.confidence_percentage >= 85

    # 2. Classification should match malicious intent (BEC, Financial Fraud, or Malicious Attachment/Phishing)
    assert assessment.classification in (
        ThreatClassification.BUSINESS_EMAIL_COMPROMISE,
        ThreatClassification.FINANCIAL_FRAUD,
        ThreatClassification.MALICIOUS_ATTACHMENT,
        ThreatClassification.PHISHING,
    )

    # 3. Indicator Verification
    indicator_ids = {ind.id for ind in assessment.indicators}
    assert "AUTH_SPF_FAIL" in indicator_ids
    assert "AUTH_DMARC_FAIL" in indicator_ids
    assert "SENDER_REPLY_TO_MISMATCH" in indicator_ids
    assert "DOMAIN_LOOKALIKE_BRAND" in indicator_ids
    assert "ATTACH_DOUBLE_EXTENSION" in indicator_ids
    assert "SOCENG_FINANCIAL_PRESSURE" in indicator_ids
    assert "SOCENG_URGENCY_PRESSURE" in indicator_ids

    # 4. Explanations & Evidence
    assert len(assessment.explanations) > 0
    top_exp = assessment.explanations[0]
    assert top_exp.score_contribution > 0
    assert len(top_exp.evidence) > 0

    # 5. Recommendations
    assert len(assessment.recommendations) > 0
    actions = [r.action for r in assessment.recommendations]
    assert any("Payment Verification" in a or "Do Not Follow Links" in a for a in actions)


def test_clean_valid_eml_threat_assessment():
    """
    Tests that valid_clean.eml produces a low threat score with passing authentication.
    """
    file_bytes = read_fixture("valid_clean.eml")
    forensic = analyze_email_bytes(file_bytes, original_filename="valid_clean.eml")

    assessment = asyncio.run(assess_email_threat(forensic))

    # 1. Clean email should produce low risk score
    assert assessment.risk_score <= 25
    assert assessment.severity in (ThreatSeverityLevel.LOW, ThreatSeverityLevel.CLEAN)
    assert assessment.classification in (ThreatClassification.BENIGN, ThreatClassification.UNKNOWN)

    # 2. Category breakdowns should all be near 0
    auth_breakdown = next(b for b in assessment.category_breakdown if b.category == ThreatCategory.AUTHENTICATION)
    assert auth_breakdown.capped_points == 0.0


def test_relative_score_comparison():
    """
    Verifies that phishing sample scores substantially higher than clean email.
    """
    phishing_bytes = read_fixture("sample_phishing.eml")
    clean_bytes = read_fixture("valid_clean.eml")

    phishing_forensic = analyze_email_bytes(phishing_bytes)
    clean_forensic = analyze_email_bytes(clean_bytes)

    phishing_assess = asyncio.run(assess_email_threat(phishing_forensic))
    clean_assess = asyncio.run(assess_email_threat(clean_forensic))

    assert phishing_assess.risk_score > clean_assess.risk_score + 45


def test_category_weight_caps_enforced():
    """
    Ensures that multiple indicators within the same category are capped properly
    and total score never exceeds 100.
    """
    # Create 5 high-weight URL indicators
    url_indicators = [
        ThreatIndicator(
            id=f"URL_TEST_{i}",
            category=ThreatCategory.URL,
            name=f"Test URL Indicator {i}",
            description="Test",
            evidence="Test URL",
            severity=ThreatSeverityLevel.HIGH,
            weight=15.0,
            confidence=1.0,
        )
        for i in range(5)
    ]

    score, breakdowns, confidence = calculate_risk_score(url_indicators)
    url_breakdown = next(b for b in breakdowns if b.category == ThreatCategory.URL)

    # Raw points = 75.0, but capped points must be <= CATEGORY_WEIGHT_CAPS[URL] (20.0)
    assert url_breakdown.raw_points == 75.0
    assert url_breakdown.capped_points == 20.0
    assert score <= 100


def test_deduplicate_indicators():
    """
    Tests that duplicate indicator IDs are coalesced without multiplying scores.
    """
    ind1 = ThreatIndicator(
        id="AUTH_SPF_FAIL",
        category=ThreatCategory.AUTHENTICATION,
        name="SPF Failure",
        description="Desc",
        evidence="Evidence 1",
        severity=ThreatSeverityLevel.HIGH,
        weight=15.0,
        confidence=0.9,
    )
    ind2 = ThreatIndicator(
        id="AUTH_SPF_FAIL",
        category=ThreatCategory.AUTHENTICATION,
        name="SPF Failure",
        description="Desc",
        evidence="Evidence 2",
        severity=ThreatSeverityLevel.HIGH,
        weight=15.0,
        confidence=1.0,
    )

    deduped = deduplicate_indicators([ind1, ind2])
    assert len(deduped) == 1
    assert deduped[0].confidence == 1.0


def test_severity_threshold_mappings():
    """
    Tests mapping of score values to standard severity levels.
    """
    assert map_score_to_severity(0) == ThreatSeverityLevel.CLEAN
    assert map_score_to_severity(15) == ThreatSeverityLevel.LOW
    assert map_score_to_severity(35) == ThreatSeverityLevel.MEDIUM
    assert map_score_to_severity(60) == ThreatSeverityLevel.HIGH
    assert map_score_to_severity(85) == ThreatSeverityLevel.CRITICAL
    assert map_score_to_severity(100) == ThreatSeverityLevel.CRITICAL


def test_api_threat_analysis_endpoint(client):
    """
    Tests POST /api/v1/analysis/threat endpoint.
    """
    file_bytes = read_fixture("sample_phishing.eml")
    forensic = analyze_email_bytes(file_bytes, original_filename="sample_phishing.eml")

    # Send forensic result as JSON body to POST /api/v1/analysis/threat
    response = client.post("/api/v1/analysis/threat", json=forensic.model_dump())

    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "severity" in data
    assert "classification" in data
    assert "explanations" in data
    assert "recommendations" in data
    assert "ai_enrichment" in data
    assert data["risk_score"] >= 70
    assert len(data["explanations"]) > 0
