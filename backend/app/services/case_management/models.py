from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class CaseStatus(str, Enum):
    NEW = "NEW"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    MONITORING = "MONITORING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CasePriority(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class IncidentVerdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    HIGH_RISK = "HIGH_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    LOW_RISK = "LOW_RISK"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE" 

class NoteCategory(str, Enum):
    OBSERVATION = "OBSERVATION"
    ANALYSIS = "ANALYSIS"
    DECISION = "DECISION"
    CONTAINMENT = "CONTAINMENT"
    EVIDENCE = "EVIDENCE"
    COMMUNICATION = "COMMUNICATION"
    HANDOFF = "HANDOFF"


class ActionType(str, Enum):
    CONTAIN = "CONTAIN"
    BLOCK_DOMAIN = "BLOCK_DOMAIN"
    BLOCK_IP = "BLOCK_IP"
    BLOCK_URL = "BLOCK_URL"
    QUARANTINE_EMAIL = "QUARANTINE_EMAIL"
    QUARANTINE_ATTACHMENT = "QUARANTINE_ATTACHMENT"
    DISABLE_SENDER = "DISABLE_SENDER"
    RESET_CREDENTIAL = "RESET_CREDENTIAL"
    PRESERVE_EVIDENCE = "PRESERVE_EVIDENCE"
    NOTIFY_SOC = "NOTIFY_SOC"
    NOTIFY_USER = "NOTIFY_USER"
    ESCALATE = "ESCALATE"
    INVESTIGATE = "INVESTIGATE"
    MONITOR = "MONITOR"


class ActionStatus(str, Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"


class ArtifactType(str, Enum):
    EMAIL = "EMAIL"
    EML_FILE = "EML_FILE"
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    ATTACHMENT = "ATTACHMENT"
    HASH = "HASH"
    TIMELINE = "TIMELINE"
    ATTACK_GRAPH = "ATTACK_GRAPH"
    THREAT_ASSESSMENT = "THREAT_ASSESSMENT"
    INTELLIGENCE_RESULT = "INTELLIGENCE_RESULT"
    AI_ASSESSMENT = "AI_ASSESSMENT"
    BLOCKCHAIN_ANCHOR = "BLOCKCHAIN_ANCHOR"


class CaseArtifact(BaseModel):
    artifact_id: str = Field(..., description="Unique artifact identifier e.g. ART-001")
    artifact_type: ArtifactType
    name: str = Field(..., description="Descriptive name of the artifact")
    reference_id: str = Field(..., description="Reference ID or raw pointer (SHA-256, URL, IP, etc.)")
    description: str = Field(default="", description="Forensic context")
    sha256: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class CaseNote(BaseModel):
    note_id: str = Field(..., description="Unique note ID e.g. NOTE-001")
    case_id: str = Field(..., description="Associated case ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    author: str = Field(default="SOC Analyst")
    content: str = Field(..., description="Note text content")
    category: NoteCategory = Field(default=NoteCategory.OBSERVATION)


class CaseAction(BaseModel):
    action_id: str = Field(..., description="Unique action ID e.g. ACT-001")
    case_id: str
    type: ActionType
    title: str
    description: str
    priority: CasePriority = Field(default=CasePriority.P2_HIGH)
    status: ActionStatus = Field(default=ActionStatus.PROPOSED)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    actor: str = Field(default="SOC Lead")
    evidence_reference: Optional[str] = None
    notes: Optional[str] = None


class CaseTimelineEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str
    title: str
    description: str
    source: str = Field(default="SOC_CASE_MANAGEMENT")
    actor: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentCase(BaseModel):
    case_id: str = Field(..., description="Unique Case ID e.g. CASE-2026-00001")
    investigation_id: str = Field(..., description="Associated Investigation ID e.g. INV-2026-00001")
    title: str = Field(..., description="Incident title")
    description: str = Field(default="", description="Incident case summary")
    status: CaseStatus = Field(default=CaseStatus.NEW)
    priority: CasePriority = Field(default=CasePriority.P3_MEDIUM)
    verdict: IncidentVerdict = Field(default=IncidentVerdict.SUSPICIOUS)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    closed_at: Optional[datetime] = None
    assigned_analyst: str = Field(default="UNASSIGNED")
    tags: List[str] = Field(default_factory=list)
    notes: List[CaseNote] = Field(default_factory=list)
    artifacts: List[CaseArtifact] = Field(default_factory=list)
    actions: List[CaseAction] = Field(default_factory=list)
    timeline: List[CaseTimelineEvent] = Field(default_factory=list)
    closure_reason: Optional[str] = None
    lessons_learned: Optional[str] = None

    # Inherited Forensic Evidence & Threat Metadata
    risk_score: int = Field(default=0, ge=0, le=100)
    severity: str = Field(default="MEDIUM")
    classification: str = Field(default="SUSPICIOUS")
    confidence: int = Field(default=85, ge=0, le=100)
    evidence_hash: str = Field(default="", description="Authoritative SHA-256 evidence digest")
    evidence_id: Optional[str] = None
    blockchain_verified: bool = Field(default=False)
    blockchain_block: Optional[int] = None
    blockchain_tx: Optional[str] = None
    sender: str = Field(default="")
    subject: str = Field(default="")


class CreateCaseRequest(BaseModel):
    investigation_id: str = Field(..., description="Investigation ID to base the case upon")
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[CasePriority] = None
    assigned_analyst: Optional[str] = "SOC-L2-ANALYST"
    tags: Optional[List[str]] = Field(default_factory=list)


class UpdateCaseRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[CasePriority] = None
    assigned_analyst: Optional[str] = None
    tags: Optional[List[str]] = None
    verdict: Optional[IncidentVerdict] = None
    root_cause: Optional[str] = None


class TransitionStatusRequest(BaseModel):
    status: CaseStatus
    reason: str = Field(..., description="Reason for lifecycle state transition")
    actor: str = Field(default="SOC Analyst")


class AssignCaseRequest(BaseModel):
    analyst: str = Field(..., description="Analyst name or ID")
    actor: str = Field(default="SOC Lead")


class AddCaseNoteRequest(BaseModel):
    content: str = Field(..., description="Note text")
    author: str = Field(default="SOC Analyst")
    category: NoteCategory = Field(default=NoteCategory.OBSERVATION)


class AddCaseTagRequest(BaseModel):
    tag: str = Field(..., description="Tag name to add")
    actor: str = Field(default="SOC Analyst")


class CreateCaseActionRequest(BaseModel):
    type: ActionType
    title: str
    description: str
    priority: Optional[CasePriority] = CasePriority.P2_HIGH
    actor: Optional[str] = "SOC Analyst"
    evidence_reference: Optional[str] = None


class UpdateActionStatusRequest(BaseModel):
    status: ActionStatus
    actor: str = Field(default="SOC Lead")
    notes: Optional[str] = None


class CloseCaseRequest(BaseModel):
    verdict: IncidentVerdict
    closure_reason: str = Field(..., min_length=5, description="Mandatory rationale for case closure")
    lessons_learned: Optional[str] = None
    actor: str = Field(default="SOC Incident Commander")


class CaseMetrics(BaseModel):
    total_cases: int
    open_cases: int
    critical_cases: int
    cases_in_investigation: int
    cases_in_containment: int
    resolved_cases: int
    closed_cases: int
    evidence_integrity_verified: int
    tamper_events: int
    average_resolution_time_minutes: float
