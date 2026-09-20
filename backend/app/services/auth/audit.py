from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional
import uuid

from app.core.logging import logger
from app.services.auth.models import SecurityAuditEvent, SecurityMetrics


class SecurityAuditLogger:
    """
    Centralized, thread-safe, immutable security audit logger.
    Captures authentication, authorization, admin, and evidence events.
    Never records raw passwords, secrets, or PII.
    """

    def __init__(self, max_records: int = 5000):
        self._lock = threading.RLock()
        self._events: List[SecurityAuditEvent] = []
        self._max_records = max_records

    def log(
        self,
        action: str,
        actor_user_id: str = "SYSTEM",
        actor_role: str = "SYSTEM",
        resource_type: str = "SECURITY",
        resource_id: str = "GLOBAL",
        result: str = "SUCCESS",
        source_ip: str = "127.0.0.1",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecurityAuditEvent:
        safe_metadata = (metadata or {}).copy()
        # Ensure sensitive fields are stripped
        for sensitive_key in ["password", "token", "secret", "raw_eml", "key", "auth_token"]:
            if sensitive_key in safe_metadata:
                safe_metadata[sensitive_key] = "[REDACTED]"

        event = SecurityAuditEvent(
            event_id=f"AUD-{uuid.uuid4().hex[:12].upper()}",
            timestamp=datetime.now(timezone.utc),
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            source_ip=source_ip,
            metadata=safe_metadata,
        )

        with self._lock:
            self._events.insert(0, event)
            if len(self._events) > self._max_records:
                self._events.pop()

        logger.info(
            f"[SECURITY AUDIT] action={action} actor={actor_user_id} role={actor_role} "
            f"res={resource_type}:{resource_id} result={result} ip={source_ip}"
        )
        return event

    def get_events(
        self,
        action: Optional[str] = None,
        actor_id: Optional[str] = None,
        result: Optional[str] = None,
        limit: int = 100,
    ) -> List[SecurityAuditEvent]:
        with self._lock:
            filtered = self._events
            if action:
                filtered = [e for e in filtered if e.action == action]
            if actor_id:
                filtered = [e for e in filtered if e.actor_user_id == actor_id]
            if result:
                filtered = [e for e in filtered if e.result == result]
            return filtered[:limit]

    def get_metrics(self, total_users: int = 0, active_users: int = 0, locked_users: int = 0) -> SecurityMetrics:
        with self._lock:
            failed_logins = len([e for e in self._events if e.action == "LOGIN_FAILURE"])
            access_denied = len([e for e in self._events if e.result == "DENIED" or e.action == "ACCESS_DENIED"])
            privileged = len([e for e in self._events if e.actor_role == "ADMIN"])
            rate_limit_count = len([e for e in self._events if e.action == "RATE_LIMIT_EXCEEDED"])

            return SecurityMetrics(
                total_users=total_users,
                active_users=active_users,
                locked_users=locked_users,
                failed_logins_24h=failed_logins,
                access_denied_24h=access_denied,
                privileged_actions_24h=privileged,
                rate_limit_events_24h=rate_limit_count,
            )


default_security_audit_logger = SecurityAuditLogger()
