from typing import List
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.security import sanitize_identifier
from app.services.ai.models import (
    AIAnalystAssessment,
    CorrelationResult,
    InvestigationAssessment,
    RelatedCase,
)
from app.services.ai.service import default_ai_service
from app.services.auth import (
    User,
    UserRole,
    get_current_user,
    require_role,
)

router = APIRouter()


@router.post(
    "/ai/analyze/{investigation_id}",
    response_model=InvestigationAssessment,
    tags=["AI Analyst"],
)
async def analyze_investigation(
    investigation_id: str,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
        )
    ),
):
    """
    Executes AI SOC Analyst assessment, multi-entity threat correlation, and attack narrative generation.
    """
    clean_id = sanitize_identifier(investigation_id)
    try:
        from app.services.investigations.service import default_case_service
        inv = await default_case_service.get_investigation(clean_id)
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation '{clean_id}' not found.",
            )
        assessment = await default_ai_service.analyze_investigation(clean_id)
        return assessment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating AI analyst assessment: {str(e)}",
        )


@router.get(
    "/ai/assessment/{investigation_id}",
    response_model=InvestigationAssessment,
    tags=["AI Analyst"],
)
async def get_assessment(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves the cached or on-demand AI analyst assessment for an investigation.
    """
    clean_id = sanitize_identifier(investigation_id)
    try:
        from app.services.investigations.service import default_case_service
        inv = await default_case_service.get_investigation(clean_id)
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation '{clean_id}' not found.",
            )
        assessment = await default_ai_service.get_assessment(clean_id)
        if not assessment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Assessment for '{clean_id}' not found.",
            )
        return assessment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving AI assessment: {str(e)}",
        )


@router.get(
    "/ai/correlation/{investigation_id}",
    response_model=CorrelationResult,
    tags=["AI Analyst"],
)
async def get_correlations(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves multi-entity correlation results (e.g. shared threat infrastructure, cross-investigation IOC links).
    """
    clean_id = sanitize_identifier(investigation_id)
    try:
        correlation = await default_ai_service.get_correlation(clean_id)
        if not correlation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Correlation for '{clean_id}' not found.",
            )
        return correlation
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error performing entity correlation: {str(e)}",
        )


@router.get(
    "/ai/related-cases/{investigation_id}",
    response_model=List[RelatedCase],
    tags=["AI Analyst"],
)
async def get_related_cases(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
):
    """
    Finds related past and active investigations based on threat similarity and shared attacker infrastructure.
    """
    clean_id = sanitize_identifier(investigation_id)
    try:
        related = await default_ai_service.get_related_cases(clean_id)
        return related
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error finding related cases: {str(e)}",
        )


@router.post(
    "/ai/refresh/{investigation_id}",
    response_model=InvestigationAssessment,
    tags=["AI Analyst"],
)
async def refresh_assessment(
    investigation_id: str,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
        )
    ),
):
    """
    Forces a cache invalidation and re-generates AI analyst assessments.
    """
    clean_id = sanitize_identifier(investigation_id)
    try:
        from app.services.investigations.service import default_case_service
        inv = await default_case_service.get_investigation(clean_id)
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation '{clean_id}' not found.",
            )
        assessment = await default_ai_service.refresh_assessment(clean_id)
        return assessment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error refreshing AI assessment: {str(e)}",
        )
