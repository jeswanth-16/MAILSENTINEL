from datetime import datetime, timezone
import threading
from typing import Dict, List, Optional

from app.core.security import hash_password
from app.services.auth.models import User, UserRole


class UserRepository:
    """
    Thread-safe repository for user credentials, roles, and account status.
    Pre-seeded with default SOC accounts for immediate operational use.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._users: Dict[str, User] = {}
        self._by_email: Dict[str, str] = {}  # email.lower() -> user_id
        self._seeded = False
        self.ensure_seeded()

    def ensure_seeded(self):
        with self._lock:
            if self._seeded:
                return

            default_accounts = [
                (
                    "USR-001",
                    "admin@mailsentinel.local",
                    "SOC Administrator",
                    UserRole.ADMIN,
                    "Admin@12345!",
                ),
                (
                    "USR-002",
                    "analyst@mailsentinel.local",
                    "SOC Tier-2 Analyst",
                    UserRole.SOC_ANALYST,
                    "Analyst@12345!",
                ),
                (
                    "USR-003",
                    "senior@mailsentinel.local",
                    "Lead Forensics Specialist",
                    UserRole.SENIOR_ANALYST,
                    "Senior@12345!",
                ),
                (
                    "USR-004",
                    "responder@mailsentinel.local",
                    "Incident Response Officer",
                    UserRole.INCIDENT_RESPONDER,
                    "Responder@12345!",
                ),
                (
                    "USR-005",
                    "auditor@mailsentinel.local",
                    "Forensic Evidence Auditor",
                    UserRole.AUDITOR,
                    "Auditor@12345!",
                ),
                (
                    "USR-006",
                    "viewer@mailsentinel.local",
                    "Executive SOC Viewer",
                    UserRole.VIEWER,
                    "Viewer@12345!",
                ),
            ]

            for uid, email, name, role, plain_pw in default_accounts:
                user = User(
                    id=uid,
                    email=email.lower().strip(),
                    full_name=name,
                    role=role,
                    is_active=True,
                    is_locked=False,
                    failed_login_attempts=0,
                    locked_until=None,
                    created_at=datetime.now(timezone.utc),
                    hashed_password=hash_password(plain_pw),
                )
                self._users[uid] = user
                self._by_email[email.lower().strip()] = uid

            self._seeded = True

    def get_by_id(self, user_id: str) -> Optional[User]:
        with self._lock:
            return self._users.get(user_id)

    def get_by_email(self, email: str) -> Optional[User]:
        with self._lock:
            user_id = self._by_email.get(email.lower().strip())
            if user_id:
                return self._users.get(user_id)
            return None

    def list_users(self) -> List[User]:
        with self._lock:
            return list(self._users.values())

    def save(self, user: User) -> User:
        with self._lock:
            self._users[user.id] = user
            self._by_email[user.email.lower().strip()] = user.id
            return user

    def delete(self, user_id: str) -> bool:
        with self._lock:
            user = self._users.pop(user_id, None)
            if user:
                self._by_email.pop(user.email.lower().strip(), None)
                return True
            return False


default_user_repository = UserRepository()
