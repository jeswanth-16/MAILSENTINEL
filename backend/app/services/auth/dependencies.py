from typing import Callable, List, Optional
from fastapi import Depends, HTTPException, Header, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.security import decode_access_token
from app.services.auth.audit import default_security_audit_logger
from app.services.auth.models import User, UserRole
from app.services.auth.rate_limiter import default_rate_limiter
from app.services.auth.rbac import has_permission
from app.services.auth.repository import default_user_repository

# Optional HTTPBearer to cleanly extract Authorization header
security_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> User:
    """
    Authenticates the incoming request via JWT Bearer Token.
    Returns the authenticated User model.
    Raises HTTP 401 Unauthorized if missing, invalid, or expired.
    """
    token: Optional[str] = None
    if credentials:
        token = credentials.credentials
    else:
        # Check Authorization header directly or custom header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    if not token:
        # If REQUIRE_AUTH is False and dev mode fallback allowed, fallback to default admin
        if not settings.REQUIRE_AUTH:
            user = default_user_repository.get_by_email("admin@mailsentinel.local")
            if user:
                return user

        default_security_audit_logger.log(
            action="ACCESS_DENIED",
            actor_user_id="ANONYMOUS",
            actor_role="GUEST",
            resource_type="API",
            resource_id=request.url.path,
            result="DENIED",
            source_ip=request.client.host if request.client else "127.0.0.1",
            metadata={"reason": "Missing or malformed Authorization header"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided or are invalid.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if not payload:
        default_security_audit_logger.log(
            action="ACCESS_DENIED",
            actor_user_id="ANONYMOUS",
            actor_role="GUEST",
            resource_type="API",
            resource_id=request.url.path,
            result="DENIED",
            source_ip=request.client.host if request.client else "127.0.0.1",
            metadata={"reason": "Invalid or expired token"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = default_user_repository.get_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account associated with this token was not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    if user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is temporarily locked due to security policy.",
        )

    return user


async def get_current_active_user(user: User = Depends(get_current_user)) -> User:
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user account")
    return user


def require_role(*allowed_roles: UserRole) -> Callable:
    """
    FastAPI dependency enforcing that the authenticated user possesses one of the allowed roles.
    Raises HTTP 403 Forbidden with security audit logging if unauthorized.
    """
    async def role_checker(
        request: Request,
        user: User = Depends(get_current_user),
    ) -> User:
        if user.role not in allowed_roles:
            default_security_audit_logger.log(
                action="ACCESS_DENIED",
                actor_user_id=user.id,
                actor_role=user.role.value,
                resource_type="ENDPOINT",
                resource_id=request.url.path,
                result="DENIED",
                source_ip=request.client.host if request.client else "127.0.0.1",
                metadata={"required_roles": [r.value for r in allowed_roles], "user_role": user.role.value},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: requires one of roles {[r.value for r in allowed_roles]}.",
            )
        return user

    return role_checker


def require_permission(permission: str) -> Callable:
    """
    FastAPI dependency enforcing that the user has a specific fine-grained permission.
    """
    async def perm_checker(
        request: Request,
        user: User = Depends(get_current_user),
    ) -> User:
        if not has_permission(user.role, permission):
            default_security_audit_logger.log(
                action="ACCESS_DENIED",
                actor_user_id=user.id,
                actor_role=user.role.value,
                resource_type="PERMISSION",
                resource_id=permission,
                result="DENIED",
                source_ip=request.client.host if request.client else "127.0.0.1",
                metadata={"required_permission": permission, "user_role": user.role.value},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: user role '{user.role.value}' lacks permission '{permission}'.",
            )
        return user

    return perm_checker


def rate_limit(max_requests: int = 60, window_seconds: int = 60) -> Callable:
    """
    FastAPI dependency that rate limits requests based on client IP or user ID.
    Raises HTTP 429 Too Many Requests if threshold is exceeded.
    """
    async def limiter(request: Request):
        if not settings.RATE_LIMIT_ENABLED:
            return

        client_ip = request.client.host if request.client else "127.0.0.1"
        key = f"{client_ip}:{request.url.path}"

        allowed, remaining = default_rate_limiter.is_allowed(
            key=key, max_requests=max_requests, window_seconds=window_seconds
        )
        if not allowed:
            default_security_audit_logger.log(
                action="RATE_LIMIT_EXCEEDED",
                actor_user_id="ANONYMOUS",
                actor_role="GUEST",
                resource_type="RATE_LIMIT",
                resource_id=key,
                result="DENIED",
                source_ip=client_ip,
                metadata={"max_requests": max_requests, "window_seconds": window_seconds},
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: maximum {max_requests} requests per {window_seconds} seconds.",
            )

    return limiter
