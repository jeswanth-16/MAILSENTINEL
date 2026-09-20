from typing import List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status

from app.core.security import sanitize_identifier
from app.schemas.investigation import (
    AddNoteRequest,
    AnalystNote,
    AssignAnalystRequest,
    CreateInvestigationRequest,
    DashboardStatsResponse,
    EscalateRequest,
    FalsePositiveRequest,
    Investigation,
    InvestigationListResponse,
    InvestigationOverview,
    InvestigationSummary,
    RunFullInvestigationResponse,
    UpdateInvestigationRequest,
    UpdateStatusRequest,
    UpdateTagsRequest,
)
from app.services.ai.models import InvestigationAssessment
from app.services.auth import (
    User,
    UserRole,
    get_current_user,
    require_role,
)
from app.services.investigations.service import default_case_service

router = APIRouter()


@router.get("/investigations", response_model=InvestigationListResponse, tags=["Investigations"])
async def list_investigations(
    status: Optional[str] = Query(None, description="Filter by case status e.g. INVESTIGATING, TRIAGING, NEW"),
    severity: Optional[str] = Query(None, description="Filter by severity e.g. CRITICAL, HIGH, MEDIUM, LOW, CLEAN"),
    classification: Optional[str] = Query(None, description="Filter by threat classification"),
    search: Optional[str] = Query(None, description="Search term across ID, title, sender, subject, or tags"),
    sort_by: str = Query("updated_at", description="Sort field: updated_at, created_at, risk_score"),
    descending: bool = Query(True, description="Sort descending or ascending"),
    current_user: User = Depends(get_current_user),
):
    """
    Returns active and recent investigations filtered and sorted by parameters.
    """
    cases = await default_case_service.list_investigations(
        status=status,
        severity=severity,
        classification=classification,
        search=search,
        sort_by=sort_by,
        descending=descending,
    )

    summaries = [
        InvestigationSummary(
            id=c.id,
            case_number=c.case_number,
            title=c.title,
            sender=c.sender or "UNKNOWN",
            subject=c.subject or "NO_SUBJECT",
            severity=c.severity.value if hasattr(c.severity, "value") else str(c.severity),
            threat_score=c.risk_score,
            risk_score=c.risk_score,
            classification=c.classification.value if hasattr(c.classification, "value") else str(c.classification),
            confidence=c.confidence,
            status=c.status.value if hasattr(c.status, "value") else str(c.status),
            analyst=c.assigned_analyst,
            priority=c.priority.value if hasattr(c.priority, "value") else str(c.priority),
            tags=c.tags,
            evidence_hash=c.evidence_hash,
            blockchain_verified=c.blockchain_verified,
            blockchain_status=c.blockchain_status,
            created_at=c.created_at,
            updated_at=c.updated_at,
        )
        for c in cases
    ]

    return InvestigationListResponse(
        total=len(summaries),
        investigations=summaries,
    )


@router.get("/investigations/stats/dashboard", response_model=DashboardStatsResponse, tags=["Investigations"])
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    """
    Returns aggregated real-time SOC metrics, severity distributions, and threat trends.
    """
    return await default_case_service.get_dashboard_stats()


@router.post("/investigations", response_model=Investigation, status_code=status.HTTP_201_CREATED, tags=["Investigations"])
async def create_investigation(
    req: CreateInvestigationRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    """
    Creates a new investigation case.
    """
    return await default_case_service.create_investigation(
        title=req.title,
        description=req.description or "",
        source=req.source or "SOC_MANUAL",
        severity=req.severity,
        classification=req.classification,
        risk_score=req.risk_score or 0,
        assigned_analyst=req.assigned_analyst or current_user.full_name,
        priority=req.priority,
        tags=req.tags or [],
        sender=req.sender or "",
        subject=req.subject or "",
        evidence_hash=req.evidence_hash or "",
    )


@router.post("/investigations/run-full", response_model=RunFullInvestigationResponse, tags=["Investigations"])
async def run_full_investigation(
    file: UploadFile = File(..., description="Raw .EML file to analyze and triage"),
    analyst: str = Form("SOC-L2-ANALYST", description="Assigned analyst name"),
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    """
    Executes the entire end-to-end automated SOC triage workflow:
    Forensic Parsing -> Threat Scoring -> Intel Enrichment -> Graph & Timeline -> Blockchain Anchor -> Case Creation.
    """
    if not file.filename.lower().endswith((".eml", ".msg", ".txt", ".mail")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be an email message with .eml, .msg, or .txt extension.",
        )

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    result = await default_case_service.run_full_investigation(
        file_bytes=file_bytes,
        filename=file.filename,
        analyst=analyst or current_user.full_name,
    )
    return result


@router.get("/investigations/{investigation_id}", response_model=Investigation, tags=["Investigations"])
async def get_investigation(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
):
    clean_id = sanitize_identifier(investigation_id)
    case = await default_case_service.get_investigation(clean_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return case


@router.patch("/investigations/{investigation_id}", response_model=Investigation, tags=["Investigations"])
async def update_investigation(
    investigation_id: str,
    req: UpdateInvestigationRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(investigation_id)
    updates = req.model_dump(exclude_unset=True) if hasattr(req, "model_dump") else req.dict(exclude_unset=True)
    updated = await default_case_service.update_investigation(clean_id, updates)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return updated


@router.delete("/investigations/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Investigations"])
async def delete_investigation(
    investigation_id: str,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
        )
    ),
):
    clean_id = sanitize_identifier(investigation_id)
    deleted = await default_case_service.delete_investigation(clean_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return None


@router.get("/investigations/{investigation_id}/overview", response_model=InvestigationOverview, tags=["Investigations"])
async def get_investigation_overview(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
):
    clean_id = sanitize_identifier(investigation_id)
    overview = await default_case_service.get_overview(clean_id)
    if not overview:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return overview


@router.post("/investigations/{investigation_id}/notes", response_model=AnalystNote, tags=["Investigations"])
async def add_investigation_note(
    investigation_id: str,
    req: AddNoteRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(investigation_id)
    note = await default_case_service.add_note(
        investigation_id=clean_id,
        content=req.content,
        author=req.author or current_user.full_name,
        note_type=req.note_type,
    )
    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return note


@router.delete("/investigations/{investigation_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Investigations"])
async def delete_investigation_note(
    investigation_id: str,
    note_id: str,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
        )
    ),
):
    clean_id = sanitize_identifier(investigation_id)
    deleted = await default_case_service.delete_note(clean_id, note_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Note '{note_id}' in investigation '{clean_id}' not found.",
        )
    return None


@router.post("/investigations/{investigation_id}/assign", response_model=Investigation, tags=["Investigations"])
async def assign_analyst(
    investigation_id: str,
    req: AssignAnalystRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
        )
    ),
):
    clean_id = sanitize_identifier(investigation_id)
    case = await default_case_service.assign_analyst(clean_id, req.analyst)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return case


@router.post("/investigations/{investigation_id}/status", response_model=Investigation, tags=["Investigations"])
async def update_status(
    investigation_id: str,
    req: UpdateStatusRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(investigation_id)
    case = await default_case_service.update_status(
        investigation_id=clean_id,
        new_status=req.status,
        reason=req.reason or "",
        analyst=req.analyst or current_user.full_name,
    )
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return case


@router.post("/investigations/{investigation_id}/tags", response_model=Investigation, tags=["Investigations"])
async def update_tags(
    investigation_id: str,
    req: UpdateTagsRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(investigation_id)
    case = await default_case_service.update_investigation(clean_id, {"tags": req.tags})
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return case


@router.post("/investigations/{investigation_id}/escalate", response_model=Investigation, tags=["Investigations"])
async def escalate_investigation(
    investigation_id: str,
    req: EscalateRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(investigation_id)
    case = await default_case_service.escalate(
        investigation_id=clean_id,
        reason=req.reason,
        escalate_to=req.escalate_to or "TIER_3_INCIDENT_RESPONSE",
        analyst=req.analyst or current_user.full_name,
    )
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return case


@router.post("/investigations/{investigation_id}/false-positive", response_model=Investigation, tags=["Investigations"])
async def mark_false_positive(
    investigation_id: str,
    req: FalsePositiveRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
        )
    ),
):
    clean_id = sanitize_identifier(investigation_id)
    case = await default_case_service.mark_false_positive(
        investigation_id=clean_id,
        reason=req.reason,
        analyst=req.analyst or current_user.full_name,
    )
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return case


@router.get("/investigations/{investigation_id}/report", tags=["Investigations"])
async def get_investigation_report(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
):
    clean_id = sanitize_identifier(investigation_id)
    report = await default_case_service.get_report_data(clean_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found.",
        )
    return report


@router.get("/investigations/{investigation_id}/assessment", response_model=InvestigationAssessment, tags=["Investigations"])
async def get_investigation_assessment(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves the Phase 4 Automated Threat Analysis & Forensic Decision Engine assessment for an investigation.
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
        from app.services.ai.service import default_ai_service
        assessment = await default_ai_service.get_assessment(clean_id)
        if not assessment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Assessment for investigation '{clean_id}' not found.",
            )
        return assessment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error evaluating investigation assessment: {str(e)}",
        )


@router.post("/investigations/{investigation_id}/assessment/recalculate", response_model=InvestigationAssessment, tags=["Investigations"])
async def recalculate_investigation_assessment(
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
    Forces recalculation of the forensic decision engine assessment and logs audit trail.
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
        from app.services.ai.service import default_ai_service
        assessment = await default_ai_service.refresh_assessment(clean_id)
        return assessment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error recalculating assessment: {str(e)}",
        )

