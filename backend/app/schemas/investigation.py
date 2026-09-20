from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.services.investigations.models import (
    InvestigationStatus,
    InvestigationSeverity,
    InvestigationClassification,
    InvestigationPriority,
    NoteType,
    AnalystNote,
    Investigation,
    InvestigationOverview,
)


class InvestigationSummary(BaseModel):
    id: str = Field(..., description="Investigation ID, e.g. INV-2026-00001")
    case_number: Optional[str] = Field(default=None, description="Internal case reference")
    title: str = Field(..., description="Case Title")
    sender: str = Field(..., description="Suspect Sender Address")
    subject: str = Field(..., description="Email Subject")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, CLEAN")
    threat_score: int = Field(..., ge=0, le=100, description="Calculated threat risk score (0-100)")
    risk_score: Optional[int] = Field(default=None, description="Alias for threat_score")
    classification: Optional[str] = Field(default=None, description="Threat Classification")
    confidence: Optional[int] = Field(default=85, description="Model/Rule confidence percentage")
    status: str = Field(..., description="Investigation status: NEW, TRIAGING, INVESTIGATING, etc.")
    analyst: str = Field(..., description="Assigned SOC Analyst")
    assigned_analyst: Optional[str] = Field(default=None, description="Alias for analyst")
    priority: Optional[str] = Field(default="P3_MEDIUM", description="Case Priority")
    tags: List[str] = Field(default_factory=list)
    evidence_hash: str = Field(..., description="SHA-256 hash of core evidence")
    blockchain_verified: bool = Field(default=False, description="Verification status on blockchain ledger")
    blockchain_status: Optional[str] = Field(default="PENDING")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class InvestigationListResponse(BaseModel):
    total: int
    investigations: List[InvestigationSummary]


class CreateInvestigationRequest(BaseModel):
    title: str = Field(..., description="Case Title")
    description: Optional[str] = Field(default="")
    source: Optional[str] = Field(default="SOC_MANUAL")
    severity: Optional[InvestigationSeverity] = Field(default=InvestigationSeverity.MEDIUM)
    classification: Optional[InvestigationClassification] = Field(default=InvestigationClassification.SUSPICIOUS)
    risk_score: Optional[int] = Field(default=0, ge=0, le=100)
    assigned_analyst: Optional[str] = Field(default="UNASSIGNED")
    priority: Optional[InvestigationPriority] = Field(default=InvestigationPriority.P3_MEDIUM)
    tags: Optional[List[str]] = Field(default_factory=list)
    sender: Optional[str] = Field(default="")
    subject: Optional[str] = Field(default="")
    evidence_hash: Optional[str] = Field(default="")


class UpdateInvestigationRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[InvestigationStatus] = None
    severity: Optional[InvestigationSeverity] = None
    classification: Optional[InvestigationClassification] = None
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    assigned_analyst: Optional[str] = None
    priority: Optional[InvestigationPriority] = None
    tags: Optional[List[str]] = None
    verdict_summary: Optional[str] = None


class AddNoteRequest(BaseModel):
    author: Optional[str] = Field(default="SOC Analyst")
    content: str = Field(..., description="Note text or decision")
    note_type: Optional[NoteType] = Field(default=NoteType.NOTE)


class AssignAnalystRequest(BaseModel):
    analyst: str = Field(..., description="Analyst name or ID to assign")


class UpdateStatusRequest(BaseModel):
    status: InvestigationStatus = Field(..., description="New investigation status")
    reason: Optional[str] = Field(default="Status transition updated by analyst")
    analyst: Optional[str] = Field(default="SOC Analyst")


class UpdateTagsRequest(BaseModel):
    tags: List[str] = Field(..., description="List of tags to assign")


class EscalateRequest(BaseModel):
    reason: str = Field(..., description="Justification for escalation")
    escalate_to: Optional[str] = Field(default="TIER_3_INCIDENT_RESPONSE")
    analyst: Optional[str] = Field(default="SOC Analyst")


class FalsePositiveRequest(BaseModel):
    reason: str = Field(..., description="Reasoning for false positive classification")
    analyst: Optional[str] = Field(default="SOC Analyst")


class RunFullInvestigationResponse(BaseModel):
    investigation: Investigation
    steps_completed: List[str]
    verdict: Dict[str, Any]


class DashboardStatsResponse(BaseModel):
    total_investigations: int
    critical_cases: int
    high_cases: int
    medium_cases: int
    low_clean_cases: int
    cases_today: int
    blockchain_verified_count: int
    blockchain_verified_percentage: float
    tamper_alerts: int
    mean_latency_seconds: float
    classification_breakdown: Dict[str, int]
    status_breakdown: Dict[str, int]
    top_source_ips: List[Dict[str, Any]]
    top_domains: List[Dict[str, Any]]
    top_countries: List[Dict[str, Any]]
