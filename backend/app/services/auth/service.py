from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
import uuid

from app.core.config import settings
from app.core.logging import logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.services.auth.audit import default_security_audit_logger
from app.services.auth.models import (
    LoginRequest,
    RegisterRequest,
    SecurityMetrics,
    TokenResponse,
    User,
    UserResponse,
    UserRole,
)
from app.services.auth.repository import UserRepository, default_user_repository


class AuthService:
    """
    Core Authentication & Identity Service for MAILSENTINEL.
    Manages logins, failed-attempt tracking, temporary account lockouts,
    token lifecycle, user provisioning, and RBAC administrative functions.
    """

    def __init__(self, repository: Optional[UserRepository] = None):
        self.repo = repository or default_user_repository
        self.audit = default_security_audit_logger

    def to_response(self, user: User) -> UserResponse:
        return UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            is_active=user.is_active,
            is_locked=user.is_locked,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )

    def authenticate_user(
        self, login_req: LoginRequest, source_ip: str = "127.0.0.1"
    ) -> Tuple[Optional[User], Optional[str]]:
        """
        Authenticates user with password verification, failed login tracking, and account lockout.
        Returns (user, error_message).
        """
        email = login_req.email.lower().strip()
        user = self.repo.get_by_email(email)

        if not user:
            self.audit.log(
                action="LOGIN_FAILURE",
                actor_user_id="UNKNOWN",
                actor_role="GUEST",
                resource_type="AUTH",
                resource_id=email,
                result="FAILURE",
                source_ip=source_ip,
                metadata={"reason": "User not found"},
            )
            return None, "Invalid email or password"

        now = datetime.now(timezone.utc)

        # Check temporary lockout
        if user.is_locked:
            if user.locked_until and now < user.locked_until:
                remaining = int((user.locked_until - now).total_seconds() / 60) + 1
                self.audit.log(
                    action="LOGIN_BLOCKED_LOCKED",
                    actor_user_id=user.id,
                    actor_role=user.role.value,
                    resource_type="AUTH",
                    resource_id=user.id,
                    result="DENIED",
                    source_ip=source_ip,
                    metadata={"locked_until": str(user.locked_until)},
                )
                return None, f"Account is temporarily locked. Try again in {remaining} minute(s)."
            else:
                # Lockout expired, reset lock
                user.is_locked = False
                user.locked_until = None
                user.failed_login_attempts = 0
                self.repo.save(user)

        if not user.is_active:
            self.audit.log(
                action="LOGIN_BLOCKED_INACTIVE",
                actor_user_id=user.id,
                actor_role=user.role.value,
                resource_type="AUTH",
                resource_id=user.id,
                result="DENIED",
                source_ip=source_ip,
            )
            return None, "Account is disabled. Please contact SOC administrator."

        # Verify password
        if not verify_password(login_req.password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
                user.is_locked = True
                user.locked_until = now + timedelta(minutes=settings.LOCKOUT_MINUTES)
                self.audit.log(
                    action="ACCOUNT_LOCKED",
                    actor_user_id=user.id,
                    actor_role=user.role.value,
                    resource_type="AUTH",
                    resource_id=user.id,
                    result="FAILURE",
                    source_ip=source_ip,
                    metadata={"failed_attempts": user.failed_login_attempts},
                )
            self.repo.save(user)

            self.audit.log(
                action="LOGIN_FAILURE",
                actor_user_id=user.id,
                actor_role=user.role.value,
                resource_type="AUTH",
                resource_id=user.id,
                result="FAILURE",
                source_ip=source_ip,
                metadata={"failed_attempts": user.failed_login_attempts},
            )
            return None, "Invalid email or password"

        # Successful login: reset failed attempts
        user.failed_login_attempts = 0
        user.is_locked = False
        user.locked_until = None
        user.last_login_at = now
        self.repo.save(user)

        self.audit.log(
            action="LOGIN_SUCCESS",
            actor_user_id=user.id,
            actor_role=user.role.value,
            resource_type="AUTH",
            resource_id=user.id,
            result="SUCCESS",
            source_ip=source_ip,
        )

        return user, None

    def create_tokens(self, user: User) -> TokenResponse:
        """
        Generates access token and response payload.
        """
        token_data = {
            "sub": user.id,
            "email": user.email,
            "role": user.role.value,
            "name": user.full_name,
        }
        access_token = create_access_token(token_data)
        expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
            user=self.to_response(user),
        )

    def register_user(
        self,
        req: RegisterRequest,
        creator: Optional[User] = None,
        source_ip: str = "127.0.0.1",
    ) -> User:
        """
        Registers a new SOC user.
        """
        email = req.email.lower().strip()
        if self.repo.get_by_email(email):
            raise ValueError(f"User with email '{email}' already exists")

        if len(req.password) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")

        user_id = f"USR-{uuid.uuid4().hex[:6].upper()}"
        user = User(
            id=user_id,
            email=email,
            full_name=req.full_name.strip(),
            role=req.role or UserRole.SOC_ANALYST,
            is_active=True,
            is_locked=False,
            failed_login_attempts=0,
            locked_until=None,
            created_at=datetime.now(timezone.utc),
            hashed_password=hash_password(req.password),
        )
        self.repo.save(user)

        self.audit.log(
            action="USER_CREATED",
            actor_user_id=creator.id if creator else "SELF",
            actor_role=creator.role.value if creator else "GUEST",
            resource_type="USER",
            resource_id=user_id,
            result="SUCCESS",
            source_ip=source_ip,
            metadata={"email": email, "role": user.role.value},
        )
        return user

    def reset_password(self, user_id: str, new_password: str, actor: User, source_ip: str = "127.0.0.1") -> User:
        user = self.repo.get_by_id(user_id)
        if not user:
            raise ValueError(f"User '{user_id}' not found")

        if len(new_password) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")

        user.hashed_password = hash_password(new_password)
        user.is_locked = False
        user.failed_login_attempts = 0
        user.locked_until = None
        self.repo.save(user)

        self.audit.log(
            action="PASSWORD_RESET",
            actor_user_id=actor.id,
            actor_role=actor.role.value,
            resource_type="USER",
            resource_id=user_id,
            result="SUCCESS",
            source_ip=source_ip,
        )
        return user

    def update_role(self, user_id: str, new_role: UserRole, actor: User, source_ip: str = "127.0.0.1") -> User:
        user = self.repo.get_by_id(user_id)
        if not user:
            raise ValueError(f"User '{user_id}' not found")

        old_role = user.role.value
        user.role = new_role
        self.repo.save(user)

        self.audit.log(
            action="ROLE_UPDATED",
            actor_user_id=actor.id,
            actor_role=actor.role.value,
            resource_type="USER",
            resource_id=user_id,
            result="SUCCESS",
            source_ip=source_ip,
            metadata={"old_role": old_role, "new_role": new_role.value},
        )
        return user

    def update_status(self, user_id: str, is_active: bool, actor: User, source_ip: str = "127.0.0.1") -> User:
        user = self.repo.get_by_id(user_id)
        if not user:
            raise ValueError(f"User '{user_id}' not found")

        user.is_active = is_active
        self.repo.save(user)

        self.audit.log(
            action="USER_STATUS_UPDATED",
            actor_user_id=actor.id,
            actor_role=actor.role.value,
            resource_type="USER",
            resource_id=user_id,
            result="SUCCESS",
            source_ip=source_ip,
            metadata={"is_active": is_active},
        )
        return user

    def list_all_users(self) -> List[UserResponse]:
        users = self.repo.list_users()
        return [self.to_response(u) for u in users]

    def get_security_metrics(self) -> SecurityMetrics:
        users = self.repo.list_users()
        total = len(users)
        active = len([u for u in users if u.is_active])
        locked = len([u for u in users if u.is_locked])
        return self.audit.get_metrics(total_users=total, active_users=active, locked_users=locked)


default_auth_service = AuthService()
