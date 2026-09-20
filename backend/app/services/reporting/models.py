from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class ReportType(str, Enum):
    EXECUTIVE = "EXECUTIVE"
    FORENSIC = "FORENSIC"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    FULL_INVESTIGATION = "FULL_INVESTIGATION"


class ReportStatus(str, Enum):
    GENERATED = "GENERATED"
    VERIFIED = "VERIFIED"
    TAMPER_DETECTED = "TAMPER_DETECTED"
    ARCHIVED = "ARCHIVED"


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    DOMAIN_REPUTATION = "DOMAIN_REPUTATION"
    URL_ANALYSIS = "URL_ANALYSIS"
    ATTACHMENT = "ATTACHMENT"
    ANOMALY = "ANOMALY"
    BEHAVIORAL = "BEHAVIORAL"
    NETWORK = "NETWORK"


class ReportFinding(BaseModel):
    finding_id: str = Field(..., description="Unique finding ID e.g. F-001")
    title: str = Field(..., description="Finding title")
    severity: FindingSeverity = Field(default=FindingSeverity.HIGH)
    category: FindingCategory = Field(default=FindingCategory.ANOMALY)
    description: str = Field(..., description="Detailed description of what was detected")
    evidence_reference: str = Field(..., description="Evidence reference key e.g. EV-001")
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    impact: str = Field(..., description="Potential security impact")
    recommendation: str = Field(..., description="Recommended mitigation step")


class ReportEvidenceReference(BaseModel):
    reference_id: str = Field(..., description="Reference ID e.g. EV-001")
    evidence_type: str = Field(..., description="Type of evidence e.g. EMAIL_EML, HEADER_RECEIVED")
    description: str = Field(..., description="Description of evidence piece")
    sha256: Optional[str] = Field(None, description="SHA-256 cryptographic digest")
    source_locator: str = Field(default="", description="Origin or field pointer")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ReportRecommendation(BaseModel):
    recommendation_id: str = Field(..., description="Recommendation ID e.g. REC-001")
    priority: str = Field(default="P1_CRITICAL")
    category: str = Field(default="CONTAINMENT")
    title: str = Field(..., description="Recommendation title")
    action: str = Field(..., description="Specific response action required")
    rationale: str = Field(..., description="Grounding justification")


class ReportSignature(BaseModel):
    signer_name: str = Field(default="Lead Forensic Examiner")
    role: str = Field(default="SOC Security Analyst")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    signature_hash: str = Field(..., description="HMAC or cryptographic signature hash")
    signature_algorithm: str = Field(default="SHA-256/ECDSA-SECP256K1")


class ReportMetadata(BaseModel):
    report_id: str = Field(..., description="Unique report ID e.g. RPT-2026-00001")
    case_id: str = Field(..., description="Associated case ID e.g. CASE-2026-00001")
    investigation_id: Optional[str] = Field(None, description="Associated investigation ID")
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str = Field(default="SOC Security Analyst")
    report_type: ReportType = Field(default=ReportType.FULL_INVESTIGATION)
    classification: str = Field(default="MALICIOUS")
    severity: str = Field(default="HIGH")
    risk_score: int = Field(default=75, ge=0, le=100)
    version: str = Field(default="1.0")
    evidence_sha256: str = Field(..., description="SHA-256 of the primary evidence")
    blockchain_status: str = Field(default="PENDING")
    blockchain_tx_hash: Optional[str] = None
    blockchain_block_number: Optional[int] = None
    report_sha256: Optional[str] = None


class ReportSection(BaseModel):
    section_id: str
    title: str
    order: int
    content: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


class ForensicReport(BaseModel):
    metadata: ReportMetadata
    executive_summary: Dict[str, Any] = Field(default_factory=dict)
    case_info: Dict[str, Any] = Field(default_factory=dict)
    evidence_info: Dict[str, Any] = Field(default_factory=dict)
    email_metadata: Dict[str, Any] = Field(default_factory=dict)
    header_analysis: Dict[str, Any] = Field(default_factory=dict)
    auth_analysis: Dict[str, Any] = Field(default_factory=dict)
    mail_route: List[Dict[str, Any]] = Field(default_factory=list)
    ip_intelligence: List[Dict[str, Any]] = Field(default_factory=list)
    domain_intelligence: List[Dict[str, Any]] = Field(default_factory=list)
    url_analysis: List[Dict[str, Any]] = Field(default_factory=list)
    attachment_analysis: List[Dict[str, Any]] = Field(default_factory=list)
    threat_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    risk_assessment: Dict[str, Any] = Field(default_factory=dict)
    attack_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    attack_graph_summary: Dict[str, Any] = Field(default_factory=dict)
    ai_assessment: Dict[str, Any] = Field(default_factory=dict)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    correlated_entities: List[Dict[str, Any]] = Field(default_factory=list)
    response_actions: List[Dict[str, Any]] = Field(default_factory=list)
    analyst_notes: List[Dict[str, Any]] = Field(default_factory=list)
    custody_chain: List[Dict[str, Any]] = Field(default_factory=list)
    blockchain_integrity: Dict[str, Any] = Field(default_factory=dict)
    evidence_references: List[ReportEvidenceReference] = Field(default_factory=list)
    findings: List[ReportFinding] = Field(default_factory=list)
    recommendations: List[ReportRecommendation] = Field(default_factory=list)
    conclusion: str = Field(default="")
    signatures: List[ReportSignature] = Field(default_factory=list)


class ReportManifest(BaseModel):
    package_id: str = Field(..., description="Unique package ID e.g. PKG-2026-00001")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    case_id: str
    investigation_id: Optional[str] = None
    files: List[str] = Field(default_factory=list)
    file_sha256: Dict[str, str] = Field(default_factory=dict)
    original_evidence_sha256: str
    blockchain_anchor_reference: Optional[str] = None
    package_sha256: Optional[str] = None


class GenerateReportRequest(BaseModel):
    report_type: ReportType = Field(default=ReportType.FULL_INVESTIGATION)
    generated_by: str = Field(default="SOC Security Analyst")
    include_ai_assessment: bool = Field(default=True)


class VerifyReportRequest(BaseModel):
    report_content: Optional[str] = Field(None, description="Optional raw JSON content string")
    expected_hash: Optional[str] = Field(None, description="Optional expected SHA-256 hash")


class VerifyReportResponse(BaseModel):
    report_id: str
    status: ReportStatus
    stored_hash: str
    calculated_hash: str
    verified: bool
    tamper_detected: bool
    message: str
    verification_timestamp: datetime = Field(default_factory=datetime.utcnow)
