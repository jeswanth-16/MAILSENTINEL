from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    SOC_ANALYST = "SOC_ANALYST"
    SENIOR_ANALYST = "SENIOR_ANALYST"
    INCIDENT_RESPONDER = "INCIDENT_RESPONDER"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"


class User(BaseModel):
    id: str = Field(..., description="Unique user ID, e.g. USR-001")
    email: str = Field(..., description="User corporate/SOC email address")
    full_name: str = Field(..., description="Full display name")
    role: UserRole = Field(default=UserRole.SOC_ANALYST)
    is_active: bool = True
    is_locked: bool = False
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login_at: Optional[datetime] = None
    hashed_password: str = Field(..., description="PBKDF2-HMAC-SHA256 hashed password")


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    is_locked: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    full_name: str
    password: str
    role: Optional[UserRole] = UserRole.SOC_ANALYST


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class PasswordResetRequest(BaseModel):
    new_password: str


class UpdateUserRoleRequest(BaseModel):
    role: UserRole


class UpdateUserStatusRequest(BaseModel):
    is_active: bool


class SecurityAuditEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    actor_user_id: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: str
    result: str = "SUCCESS"  # SUCCESS, FAILURE, DENIED
    source_ip: str = "127.0.0.1"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityMetrics(BaseModel):
    total_users: int
    active_users: int
    locked_users: int
    failed_logins_24h: int
    access_denied_24h: int
    privileged_actions_24h: int
    rate_limit_events_24h: int
