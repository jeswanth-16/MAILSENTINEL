from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class InvestigationStatus(str, Enum):
    NEW = "NEW"
    ANALYZING = "ANALYZING"
    THREAT_ASSESSED = "THREAT_ASSESSED"
    INTELLIGENCE_COMPLETE = "INTELLIGENCE_COMPLETE"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    EVIDENCE_ANCHORED = "EVIDENCE_ANCHORED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class InvestigationSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


class InvestigationClassification(str, Enum):
    PHISHING = "PHISHING"
    BUSINESS_EMAIL_COMPROMISE = "BUSINESS_EMAIL_COMPROMISE"
    FINANCIAL_FRAUD = "FINANCIAL_FRAUD"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    MALICIOUS_ATTACHMENT = "MALICIOUS_ATTACHMENT"
    MALWARE = "MALWARE"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"


class InvestigationPriority(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class NoteType(str, Enum):
    NOTE = "NOTE"
    ACTION = "ACTION"
    DECISION = "DECISION"
    ESCALATION = "ESCALATION"
    SYSTEM = "SYSTEM"


class AnalystNote(BaseModel):
    note_id: str = Field(..., description="Unique note identifier (e.g. NOTE-001)")
    investigation_id: str = Field(..., description="Associated investigation ID")
    author: str = Field(default="SOC Analyst", description="Author of note or system agent")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Timestamp note was added")
    content: str = Field(..., description="Note text or audit event details")
    note_type: NoteType = Field(default=NoteType.NOTE, description="Categorization of note")


class Investigation(BaseModel):
    id: str = Field(..., description="Investigation ID, e.g. INV-2026-00001")
    case_number: str = Field(..., description="Internal case numbering e.g. CASE-2026-001")
    title: str = Field(..., description="Case descriptive title")
    description: str = Field(default="", description="Detailed case narrative or summary")
    source: str = Field(default="EMAIL_GATEWAY", description="Ingestion source (EMAIL_GATEWAY, SOC_MANUAL, SIEM)")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    status: InvestigationStatus = Field(default=InvestigationStatus.NEW)
    severity: InvestigationSeverity = Field(default=InvestigationSeverity.MEDIUM)
    classification: InvestigationClassification = Field(default=InvestigationClassification.SUSPICIOUS)
    risk_score: int = Field(default=0, ge=0, le=100)
    threat_score: int = Field(default=0, ge=0, le=100)
    confidence: int = Field(default=85, ge=0, le=100)
    assigned_analyst: str = Field(default="UNASSIGNED")
    analyst: str = Field(default="UNASSIGNED")
    tags: List[str] = Field(default_factory=list)
    priority: InvestigationPriority = Field(default=InvestigationPriority.P3_MEDIUM)
    
    # Forensic linkages
    email_evidence_id: Optional[str] = None
    evidence_id: Optional[str] = None
    evidence_hash: str = Field(default="", description="Primary SHA-256 evidence fingerprint")
    sender: str = Field(default="", description="Suspect sender email address")
    subject: str = Field(default="", description="Email subject line")
    
    # Blockchain integrity linkage
    blockchain_status: str = Field(default="PENDING", description="ANCHORED, VERIFIED, TAMPERED, PENDING, NONE")
    blockchain_tx: Optional[str] = None
    blockchain_block: Optional[int] = None
    blockchain_network: Optional[str] = "MAILSENTINEL-DEMO-CHAIN"
    blockchain_verified: bool = Field(default=False)
    
    # Metadata & Notes
    created_by: str = Field(default="SYSTEM_INGEST")
    notes: List[AnalystNote] = Field(default_factory=list)
    verdict_summary: Optional[str] = None
    recommended_actions: List[str] = Field(default_factory=list)

    def __init__(self, **data: Any):
        if "risk_score" in data and "threat_score" not in data:
            data["threat_score"] = data["risk_score"]
        elif "threat_score" in data and "risk_score" not in data:
            data["risk_score"] = data["threat_score"]

        if "assigned_analyst" in data and "analyst" not in data:
            data["analyst"] = data["assigned_analyst"]
        elif "analyst" in data and "assigned_analyst" not in data:
            data["assigned_analyst"] = data["analyst"]

        super().__init__(**data)


class InvestigationOverview(BaseModel):
    investigation: Investigation
    top_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    top_entities: Dict[str, Any] = Field(default_factory=dict)
    auth_summary: Dict[str, str] = Field(default_factory=dict)
    key_findings: List[str] = Field(default_factory=list)
    blockchain_summary: Dict[str, Any] = Field(default_factory=dict)
    latest_activity: List[Dict[str, Any]] = Field(default_factory=list)
