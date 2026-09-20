from datetime import datetime, timezone
from typing import Any, Optional
from app.services.email.models import EmailForensicResult
from app.services.risk.explanations import (
    generate_executive_summary,
    generate_explanations,
    generate_recommendations,
)
from app.services.risk.models import ThreatAssessmentResult
from app.services.risk.scoring import calculate_risk_score, deduplicate_indicators
from app.services.risk.thresholds import map_score_to_severity
from app.services.threat.ai import AIInputPayload, default_ai_service
from app.services.threat.classifier import classify_threat
from app.services.threat.indicators import detect_all_indicators
from app.services.threat.models import AIAnalysisResult


async def assess_email_threat(
    forensic: EmailForensicResult,
    correlation: Optional[Any] = None,
) -> ThreatAssessmentResult:
    """
    Evaluates raw forensic evidence into an explainable, deterministic threat assessment.
    Runs indicator detection, risk scoring with category caps, classification, AI enrichment, and explanation generation.
    """
    # 1. Detect all observable threat indicators
    raw_indicators = detect_all_indicators(forensic, correlation=correlation)
    indicators = deduplicate_indicators(raw_indicators)

    # 2. Calculate deterministic risk score, breakdowns, and confidence
    risk_score, category_breakdown, confidence = calculate_risk_score(indicators)

    # 3. Map score to severity level
    severity = map_score_to_severity(risk_score)

    # 4. Classify threat based on observable evidence
    classification = classify_threat(indicators, risk_score)

    # 5. Execute AI/NLP enrichment abstraction (safe fallback if offline/no key)
    ai_input = AIInputPayload(
        subject=forensic.metadata.subject,
        from_address=forensic.metadata.from_address,
        reply_to=forensic.metadata.reply_to,
        return_path=forensic.metadata.return_path,
        body_text_preview=forensic.body_analysis.normalized_text_preview,
        extracted_urls=[u.normalized_url for u in forensic.urls],
        extracted_domains=[d.domain for d in forensic.domains],
        detected_indicator_ids=[i.id for i in indicators],
    )
    ai_output = await default_ai_service.get_enrichment(ai_input)

    ai_result = AIAnalysisResult(
        available=ai_output.available,
        provider=ai_output.provider_name,
        suggested_classification=ai_output.classification,
        confidence=ai_output.confidence,
        social_engineering_signals=ai_output.social_engineering_signals,
        reasoning=ai_output.reasoning,
        status_message=ai_output.status_message,
    )

    # 6. Generate explainability breakdowns
    explanations = generate_explanations(indicators)
    summary = generate_executive_summary(risk_score, severity, classification, indicators)
    recommendations = generate_recommendations(classification, indicators)

    return ThreatAssessmentResult(
        investigation_id=forensic.investigation_id,
        risk_score=risk_score,
        severity=severity,
        classification=classification,
        confidence=confidence,
        confidence_percentage=int(round(confidence * 100)),
        summary=summary,
        indicators=indicators,
        category_breakdown=category_breakdown,
        explanations=explanations,
        recommendations=recommendations,
        ai_enrichment=ai_result,
        evaluated_at=datetime.now(timezone.utc).isoformat(),
    )
