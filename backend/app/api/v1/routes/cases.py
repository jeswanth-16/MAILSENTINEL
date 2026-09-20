from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.security import sanitize_identifier
from app.services.auth import (
    User,
    UserRole,
    default_security_audit_logger,
    get_current_user,
    require_role,
)
from app.services.case_management import (
    ActionStatus,
    AddCaseNoteRequest,
    AddCaseTagRequest,
    AssignCaseRequest,
    CaseAction,
    CaseAuditEvent,
    CaseMetrics,
    CaseNote,
    CasePriority,
    CaseStatus,
    CloseCaseRequest,
    CreateCaseActionRequest,
    CreateCaseRequest,
    IncidentCase,
    IncidentVerdict,
    InvalidCaseStateTransitionError,
    TransitionStatusRequest,
    UpdateActionStatusRequest,
    UpdateCaseRequest,
    default_incident_case_service,
)

router = APIRouter(prefix="/cases", tags=["Case Management"])


@router.post("", response_model=IncidentCase, status_code=status.HTTP_201_CREATED)
async def create_case(
    req: CreateCaseRequest,
    request: Request,
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
    Creates an incident case based upon an existing investigated email.
    Inherits all evidence references, threat scores, intelligence, timeline, and blockchain proof.
    """
    clean_inv_id = sanitize_identifier(req.investigation_id)
    case = await default_incident_case_service.create_case_from_investigation(
        investigation_id=clean_inv_id,
        title=req.title,
        description=req.description,
        priority=req.priority,
        assigned_analyst=req.assigned_analyst or current_user.full_name,
        tags=req.tags,
        actor=current_user.full_name,
    )

    default_security_audit_logger.log(
        action="CASE_CREATED",
        actor_user_id=current_user.id,
        actor_role=current_user.role.value,
        resource_type="CASE",
        resource_id=case.case_id,
        result="SUCCESS",
        source_ip=request.client.host if request.client else "127.0.0.1",
        metadata={"title": case.title, "priority": case.priority.value},
    )

    return case


@router.get("", response_model=Dict[str, Any])
async def list_cases(
    status_filter: Optional[CaseStatus] = Query(None, alias="status"),
    priority_filter: Optional[CasePriority] = Query(None, alias="priority"),
    verdict_filter: Optional[IncidentVerdict] = Query(None, alias="verdict"),
    search: Optional[str] = Query(None, description="Search term across case ID, title, sender, tags"),
    sort_by: str = Query("created_at", description="Field to sort by"),
    descending: bool = Query(True, description="Sort descending"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """
    Lists incident cases with filtering, search, pagination, and sorting.
    Accessible to all authenticated SOC roles.
    """
    cases, total = await default_incident_case_service.list_cases(
        status=status_filter,
        priority=priority_filter,
        verdict=verdict_filter,
        search=search,
        sort_by=sort_by,
        descending=descending,
        page=page,
        page_size=page_size,
    )
    return {
        "cases": [c.model_dump() if hasattr(c, "model_dump") else c.dict() for c in cases],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total > 0 else 1,
    }


@router.get("/stats/metrics", response_model=CaseMetrics)
async def get_case_metrics(current_user: User = Depends(get_current_user)):
    """
    Retrieves live SOC incident response metrics across all cases.
    """
    return await default_incident_case_service.get_case_metrics()


@router.get("/{case_id}", response_model=IncidentCase)
async def get_case(
    case_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves full details for a single incident case.
    Enforces case ID sanitization and IDOR protection.
    """
    clean_id = sanitize_identifier(case_id)
    case = await default_incident_case_service.get_case(clean_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident Case '{case_id}' not found.",
        )

    default_security_audit_logger.log(
        action="CASE_VIEWED",
        actor_user_id=current_user.id,
        actor_role=current_user.role.value,
        resource_type="CASE",
        resource_id=clean_id,
        result="SUCCESS",
        source_ip=request.client.host if request.client else "127.0.0.1",
    )

    return case


@router.patch("/{case_id}", response_model=IncidentCase)
async def update_case(
    case_id: str,
    req: UpdateCaseRequest,
    request: Request,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(case_id)
    try:
        updates = req.model_dump(exclude_unset=True) if hasattr(req, "model_dump") else req.dict(exclude_unset=True)
        case = await default_incident_case_service.update_case(
            case_id=clean_id,
            updates=updates,
            actor=current_user.full_name,
        )

        default_security_audit_logger.log(
            action="CASE_UPDATED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="CASE",
            resource_id=clean_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
        )
        return case
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/{case_id}/status", response_model=IncidentCase)
async def transition_case_status(
    case_id: str,
    req: TransitionStatusRequest,
    request: Request,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(case_id)
    try:
        case = await default_incident_case_service.transition_status(
            case_id=clean_id,
            new_status=req.new_status,
            reason=req.reason,
            actor=current_user.full_name,
        )

        default_security_audit_logger.log(
            action="CASE_STATUS_CHANGED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="CASE",
            resource_id=clean_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
            metadata={"new_status": req.new_status.value, "reason": req.reason},
        )
        return case
    except InvalidCaseStateTransitionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/{case_id}/assign", response_model=IncidentCase)
async def assign_case(
    case_id: str,
    req: AssignCaseRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
        )
    ),
):
    clean_id = sanitize_identifier(case_id)
    try:
        return await default_incident_case_service.assign_case(
            case_id=clean_id,
            analyst=req.analyst,
            actor=current_user.full_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/{case_id}/notes", response_model=CaseNote, status_code=status.HTTP_201_CREATED)
async def add_case_note(
    case_id: str,
    req: AddCaseNoteRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(case_id)
    try:
        return await default_incident_case_service.add_note(
            case_id=clean_id,
            content=req.content,
            category=req.category,
            author=current_user.full_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete("/{case_id}/notes/{note_id}", response_model=Dict[str, Any])
async def delete_case_note(
    case_id: str,
    note_id: str,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
        )
    ),
):
    clean_id = sanitize_identifier(case_id)
    try:
        success = await default_incident_case_service.delete_note(
            case_id=clean_id,
            note_id=note_id,
            actor=current_user.full_name,
        )
        return {"success": success, "message": f"Note '{note_id}' removed from case."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/{case_id}/tags", response_model=IncidentCase)
async def add_case_tag(
    case_id: str,
    req: AddCaseTagRequest,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(case_id)
    try:
        return await default_incident_case_service.add_tag(
            case_id=clean_id,
            tag=req.tag,
            actor=current_user.full_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete("/{case_id}/tags/{tag}", response_model=IncidentCase)
async def remove_case_tag(
    case_id: str,
    tag: str,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(case_id)
    try:
        return await default_incident_case_service.remove_tag(
            case_id=clean_id,
            tag=tag,
            actor=current_user.full_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/{case_id}/actions", response_model=CaseAction, status_code=status.HTTP_201_CREATED)
async def create_case_action(
    case_id: str,
    req: CreateCaseActionRequest,
    request: Request,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    clean_id = sanitize_identifier(case_id)
    try:
        action = await default_incident_case_service.create_action(
            case_id=clean_id,
            action_type=req.type,
            title=req.title,
            description=req.description,
            priority=req.priority or CasePriority.P2_HIGH,
            actor=req.actor or current_user.full_name,
            evidence_reference=req.evidence_reference,
        )

        default_security_audit_logger.log(
            action="RESPONSE_ACTION_PROPOSED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="CASE_ACTION",
            resource_id=action.action_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
            metadata={"case_id": clean_id, "action_type": req.type.value},
        )
        return action
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.patch("/{case_id}/actions/{action_id}", response_model=CaseAction)
async def update_action_status(
    case_id: str,
    action_id: str,
    req: UpdateActionStatusRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    clean_id = sanitize_identifier(case_id)
    
    # Check permissions based on the target action status
    if req.status == ActionStatus.APPROVED:
        if current_user.role not in [UserRole.ADMIN, UserRole.SENIOR_ANALYST]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Approving containment & eradication actions requires SENIOR_ANALYST or ADMIN role.",
            )
    elif req.status in [ActionStatus.IN_PROGRESS, ActionStatus.COMPLETED]:
        if current_user.role not in [UserRole.ADMIN, UserRole.SENIOR_ANALYST, UserRole.INCIDENT_RESPONDER]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Executing containment actions requires INCIDENT_RESPONDER, SENIOR_ANALYST or ADMIN role.",
            )
    elif current_user.role in [UserRole.VIEWER, UserRole.AUDITOR]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Viewers and Auditors cannot modify response actions.",
        )

    try:
        action = await default_incident_case_service.update_action_status(
            case_id=clean_id,
            action_id=action_id,
            status=req.status,
            actor=current_user.full_name,
            notes=req.notes,
        )

        default_security_audit_logger.log(
            action=f"RESPONSE_ACTION_{req.status.value}",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="CASE_ACTION",
            resource_id=action_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
            metadata={"case_id": clean_id, "new_status": req.status.value},
        )
        return action
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/{case_id}/close", response_model=IncidentCase)
async def close_case(
    case_id: str,
    req: CloseCaseRequest,
    request: Request,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
        )
    ),
):
    clean_id = sanitize_identifier(case_id)
    try:
        case = await default_incident_case_service.close_case(
            case_id=clean_id,
            verdict=req.verdict,
            root_cause=req.root_cause,
            closure_notes=req.closure_notes,
            lessons_learned=req.lessons_learned,
            actor=current_user.full_name,
        )

        default_security_audit_logger.log(
            action="CASE_CLOSED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="CASE",
            resource_id=clean_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
            metadata={"verdict": req.verdict.value, "root_cause": req.root_cause},
        )
        return case
    except InvalidCaseStateTransitionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/{case_id}/audit", response_model=List[CaseAuditEvent])
async def get_case_audit_trail(
    case_id: str,
    current_user: User = Depends(get_current_user),
):
    clean_id = sanitize_identifier(case_id)
    try:
        return await default_incident_case_service.get_audit_trail(clean_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/{case_id}/blockchain/verify", response_model=Dict[str, Any])
async def verify_case_blockchain(
    case_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    clean_id = sanitize_identifier(case_id)
    try:
        res = await default_incident_case_service.verify_case_blockchain(clean_id)
        default_security_audit_logger.log(
            action="BLOCKCHAIN_CASE_VERIFIED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="CASE",
            resource_id=clean_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/{case_id}/ai/refresh", response_model=Dict[str, Any])
async def refresh_ai_assessment(
    case_id: str,
    request: Request,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
        )
    ),
):
    clean_id = sanitize_identifier(case_id)
    try:
        res = await default_incident_case_service.refresh_ai_assessment(clean_id)
        default_security_audit_logger.log(
            action="AI_ANALYSIS_REQUESTED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="CASE",
            resource_id=clean_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
