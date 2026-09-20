from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.security import decode_access_token
from app.services.auth import (
    LoginRequest,
    PasswordResetRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
    User,
    UserResponse,
    default_auth_service,
    default_security_audit_logger,
    get_current_user,
    rate_limit,
)

router = APIRouter(prefix="/auth", tags=["Authentication & Identity"])


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit(max_requests=10, window_seconds=60))],
)
async def login(req: LoginRequest, request: Request):
    """
    Authenticates user credentials and issues a cryptographically signed access token.
    Enforces failed-login tracking, rate limiting, and temporary account lockout.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    user, err = default_auth_service.authenticate_user(req, source_ip=client_ip)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=err or "Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return default_auth_service.create_tokens(user)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, request: Request):
    """
    Registers a new SOC account.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        user = default_auth_service.register_user(req, creator=None, source_ip=client_ip)
        return default_auth_service.to_response(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(req: RefreshTokenRequest, request: Request):
    """
    Exchanges a valid refresh token for a new access token.
    """
    payload = decode_access_token(req.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    user_id = payload.get("sub")
    user = default_auth_service.repo.get_by_id(user_id)
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or locked.",
        )

    client_ip = request.client.host if request.client else "127.0.0.1"
    default_security_audit_logger.log(
        action="TOKEN_REFRESH",
        actor_user_id=user.id,
        actor_role=user.role.value,
        resource_type="AUTH",
        resource_id=user.id,
        result="SUCCESS",
        source_ip=client_ip,
    )

    return default_auth_service.create_tokens(user)


@router.post("/logout")
async def logout(request: Request, current_user: User = Depends(get_current_user)):
    """
    Logs out the current authenticated user and records an immutable audit trail.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    default_security_audit_logger.log(
        action="LOGOUT",
        actor_user_id=current_user.id,
        actor_role=current_user.role.value,
        resource_type="AUTH",
        resource_id=current_user.id,
        result="SUCCESS",
        source_ip=client_ip,
    )
    return {"status": "success", "message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """
    Returns the currently authenticated user's profile and active role.
    """
    return default_auth_service.to_response(current_user)
