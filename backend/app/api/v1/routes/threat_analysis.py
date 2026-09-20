from fastapi import APIRouter, Depends, HTTPException, status
from app.core.logging import logger
from app.services.auth import User, get_current_user
from app.services.email.models import EmailForensicResult
from app.services.risk import ThreatAssessmentResult, assess_email_threat

router = APIRouter()


@router.post(
    "/analysis/threat",
    response_model=ThreatAssessmentResult,
    status_code=status.HTTP_200_OK,
    summary="Evaluate forensic evidence into explainable threat assessment and risk score",
    tags=["Threat Detection & Risk Engine"],
)
async def assess_threat_endpoint(
    forensic: EmailForensicResult,
    current_user: User = Depends(get_current_user),
):
    """
    Takes an EmailForensicResult (from Step 5 email forensic triage) and computes:
    - Observable threat indicators across 7 categories
    - Deterministic risk score (0-100) with category caps & deduplication
    - Standardized severity level (CRITICAL, HIGH, MEDIUM, LOW, CLEAN)
    - Evidence-based threat classification
    - Structured 'Why this score' explanations and evidence contributions
    - Actionable defensive recommendations
    - Optional AI/NLP semantic enrichment (with offline fallback)
    """
    try:
        logger.info(f"Assessing threat indicators for Investigation {forensic.investigation_id} by {current_user.email}")
        assessment = await assess_email_threat(forensic)
        from app.services.forensics.service import investigation_registry
        investigation_registry.store(forensic.investigation_id, forensic, threat=assessment)
        logger.info(
            f"Threat assessment complete for {forensic.investigation_id}: "
            f"Score {assessment.risk_score} ({assessment.severity.value}) - {assessment.classification.value}"
        )
        return assessment

    except Exception as e:
        logger.error(f"Error during threat assessment for {forensic.investigation_id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to evaluate threat indicators and risk score.",
        )
