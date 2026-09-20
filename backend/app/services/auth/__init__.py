from app.services.auth.audit import SecurityAuditLogger, default_security_audit_logger
from app.services.auth.dependencies import (
    get_current_active_user,
    get_current_user,
    rate_limit,
    require_permission,
    require_role,
)
from app.services.auth.models import (
    LoginRequest,
    PasswordResetRequest,
    RefreshTokenRequest,
    RegisterRequest,
    SecurityAuditEvent,
    SecurityMetrics,
    TokenResponse,
    UpdateUserRoleRequest,
    UpdateUserStatusRequest,
    User,
    UserResponse,
    UserRole,
)
from app.services.auth.rate_limiter import InMemoryRateLimiter, default_rate_limiter
from app.services.auth.rbac import ROLE_PERMISSIONS, has_permission
from app.services.auth.repository import UserRepository, default_user_repository
from app.services.auth.service import AuthService, default_auth_service

__all__ = [
    "UserRole",
    "User",
    "UserResponse",
    "LoginRequest",
    "RegisterRequest",
    "TokenResponse",
    "RefreshTokenRequest",
    "PasswordResetRequest",
    "UpdateUserRoleRequest",
    "UpdateUserStatusRequest",
    "SecurityAuditEvent",
    "SecurityMetrics",
    "ROLE_PERMISSIONS",
    "has_permission",
    "UserRepository",
    "default_user_repository",
    "AuthService",
    "default_auth_service",
    "SecurityAuditLogger",
    "default_security_audit_logger",
    "InMemoryRateLimiter",
    "default_rate_limiter",
    "get_current_user",
    "get_current_active_user",
    "require_role",
    "require_permission",
    "rate_limit",
]
