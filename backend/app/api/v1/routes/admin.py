from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.services.auth import (
    PasswordResetRequest,
    RegisterRequest,
    SecurityAuditEvent,
    SecurityMetrics,
    UpdateUserRoleRequest,
    UpdateUserStatusRequest,
    User,
    UserResponse,
    UserRole,
    default_auth_service,
    default_security_audit_logger,
    require_role,
)

router = APIRouter(prefix="/admin", tags=["SOC Security Administration & User Management"])


@router.get("/users", response_model=List[UserResponse])
async def list_users(current_admin: User = Depends(require_role(UserRole.ADMIN))):
    """
    Lists all provisioned SOC platform users.
    Restricted to ADMIN role.
    """
    return default_auth_service.list_all_users()


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    req: RegisterRequest,
    request: Request,
    current_admin: User = Depends(require_role(UserRole.ADMIN)),
):
    """
    Creates a new SOC user account with specified role.
    Restricted to ADMIN role.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        user = default_auth_service.register_user(req, creator=current_admin, source_ip=client_ip)
        return default_auth_service.to_response(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch("/users/{user_id}/status", response_model=UserResponse)
async def update_user_status(
    user_id: str,
    req: UpdateUserStatusRequest,
    request: Request,
    current_admin: User = Depends(require_role(UserRole.ADMIN)),
):
    """
    Activates or deactivates a user account.
    Restricted to ADMIN role.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        user = default_auth_service.update_status(
            user_id=user_id, is_active=req.is_active, actor=current_admin, source_ip=client_ip
        )
        return default_auth_service.to_response(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.patch("/users/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: str,
    req: UpdateUserRoleRequest,
    request: Request,
    current_admin: User = Depends(require_role(UserRole.ADMIN)),
):
    """
    Changes a user's RBAC role.
    Restricted to ADMIN role.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        user = default_auth_service.update_role(
            user_id=user_id, new_role=req.role, actor=current_admin, source_ip=client_ip
        )
        return default_auth_service.to_response(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/users/{user_id}/reset-password", response_model=UserResponse)
async def reset_user_password(
    user_id: str,
    req: PasswordResetRequest,
    request: Request,
    current_admin: User = Depends(require_role(UserRole.ADMIN)),
):
    """
    Resets a user's password and unlocks their account.
    Restricted to ADMIN role.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        user = default_auth_service.reset_password(
            user_id=user_id, new_password=req.new_password, actor=current_admin, source_ip=client_ip
        )
        return default_auth_service.to_response(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/security/metrics", response_model=SecurityMetrics)
async def get_security_metrics(
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR)),
):
    """
    Returns security telemetry metrics for the SOC Access Dashboard.
    Restricted to ADMIN or AUDITOR role.
    """
    return default_auth_service.get_security_metrics()


@router.get("/security/audit-logs", response_model=List[SecurityAuditEvent])
async def get_security_audit_logs(
    action: Optional[str] = Query(None),
    actor_id: Optional[str] = Query(None),
    result: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR)),
):
    """
    Fetches the immutable security audit trail.
    Restricted to ADMIN or AUDITOR role.
    """
    return default_security_audit_logger.get_events(
        action=action, actor_id=actor_id, result=result, limit=limit
    )
