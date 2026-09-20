from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.security import sanitize_identifier
from app.services.auth import User, get_current_user
from app.services.email.models import EmailForensicResult
from app.services.forensics.models import TimelineResponse
from app.services.forensics.service import default_forensics_service
from app.services.forensics.timeline import build_forensic_timeline
from app.services.intelligence.models import InvestigationIntelligenceResult
from app.services.risk.models import ThreatAssessmentResult

router = APIRouter(tags=["Forensic Timeline"])


class GenerateTimelineRequest(BaseModel):
    forensic: EmailForensicResult
    threat_assessment: Optional[ThreatAssessmentResult] = None
    intelligence: Optional[InvestigationIntelligenceResult] = None


@router.get(
    "/investigations/{investigation_id}/timeline",
    response_model=TimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Get reconstructed chronological forensic timeline for an investigation",
)
async def get_investigation_timeline_endpoint(
    investigation_id: str,
    sort: str = Query("asc", description="Sort order: 'asc' or 'desc'"),
    severity: Optional[str] = Query(None, description="Filter by event severity e.g. CRITICAL, HIGH, INFO"),
    event_type: Optional[str] = Query(None, description="Filter by event type e.g. SMTP_RELAY, THREAT_INDICATOR"),
    current_user: User = Depends(get_current_user),
):
    if sort.lower() not in ("asc", "desc"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid sort parameter. Must be 'asc' or 'desc'.",
        )

    clean_id = sanitize_identifier(investigation_id)
    timeline = await default_forensics_service.get_investigation_timeline(
        investigation_id=clean_id,
        sort=sort,
        severity_filter=severity,
        event_type_filter=event_type,
    )

    if not timeline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found. Ensure email has been uploaded and analyzed.",
        )

    return timeline


@router.post(
    "/forensics/timeline",
    response_model=TimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate forensic timeline directly from forensic payloads",
)
async def generate_timeline_endpoint(
    request: GenerateTimelineRequest,
    current_user: User = Depends(get_current_user),
):
    events = build_forensic_timeline(
        forensic=request.forensic,
        threat_assessment=request.threat_assessment,
        intelligence=request.intelligence,
    )
    return TimelineResponse(
        investigation_id=request.forensic.investigation_id,
        events=events,
        total_events=len(events),
    )
