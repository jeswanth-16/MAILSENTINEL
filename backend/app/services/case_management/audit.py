from datetime import datetime
from enum import Enum
from typing import Dict, Optional, Any
from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    CASE_CREATED = "CASE_CREATED"
    STATUS_CHANGED = "STATUS_CHANGED"
    ASSIGNMENT_CHANGED = "ASSIGNMENT_CHANGED"
    NOTE_ADDED = "NOTE_ADDED"
    NOTE_DELETED = "NOTE_DELETED"
    TAG_ADDED = "TAG_ADDED"
    TAG_REMOVED = "TAG_REMOVED"
    ACTION_CREATED = "ACTION_CREATED"
    ACTION_APPROVED = "ACTION_APPROVED"
    ACTION_COMPLETED = "ACTION_COMPLETED"
    ACTION_REJECTED = "ACTION_REJECTED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    EVIDENCE_TAMPER_DETECTED = "EVIDENCE_TAMPER_DETECTED"
    CASE_CLOSED = "CASE_CLOSED"
    AI_ANALYSIS_REQUESTED = "AI_ANALYSIS_REQUESTED"


class CaseAuditEvent(BaseModel):
    audit_id: str = Field(..., description="Unique audit event ID e.g. AUD-00101")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    case_id: str
    event_type: AuditEventType
    actor: str = Field(default="SOC Analyst")
    description: str
    previous_value: Optional[str] = None
    new_value: Optional[str] = None
    related_evidence: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
