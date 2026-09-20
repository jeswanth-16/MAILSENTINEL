from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class ThreatPatternType(str, Enum):
    BUSINESS_EMAIL_COMPROMISE = "BUSINESS_EMAIL_COMPROMISE"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    MALICIOUS_ATTACHMENT = "MALICIOUS_ATTACHMENT"
    FINANCIAL_FRAUD = "FINANCIAL_FRAUD"
    RECONNAISSANCE_PHISHING = "RECONNAISSANCE_PHISHING"
    SUPPLY_CHAIN_IMPERSONATION = "SUPPLY_CHAIN_IMPERSONATION"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


class MITRETactic(str, Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class ConfidenceRating(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOT_CONFIRMED = "NOT_CONFIRMED"


class LeadCategory(str, Enum):
    MAIL_GATEWAY = "MAIL_GATEWAY"
    ENDPOINT_TELEMETRY = "ENDPOINT_TELEMETRY"
    PROXY_LOGS = "PROXY_LOGS"
    COMMUNICATION_VERIFICATION = "COMMUNICATION_VERIFICATION"
    DNS_ANALYSIS = "DNS_ANALYSIS"
    IDENTITY_ACCESS = "IDENTITY_ACCESS"


class ActionCategory(str, Enum):
    CONTAIN = "CONTAIN"
    INVESTIGATE = "INVESTIGATE"
    BLOCK = "BLOCK"
    PRESERVE = "PRESERVE"
    NOTIFY = "NOTIFY"


class MITRETechnique(BaseModel):
    technique_id: str = Field(..., description="MITRE Technique ID e.g. T1566.002")
    name: str = Field(..., description="Technique Title")
    tactic: MITRETactic = Field(default=MITRETactic.INITIAL_ACCESS)
    rationale: str = Field(..., description="Technical explanation for technique mapping")
    evidence: str = Field(..., description="Exact observable evidence justifying mapping")
    confidence: ConfidenceRating = Field(default=ConfidenceRating.HIGH)


class ThreatPattern(BaseModel):
    pattern_type: ThreatPatternType
    title: str
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    confidence_percentage: int = Field(default=90, ge=0, le=100)
    description: str
    indicators_involved: List[str] = Field(default_factory=list)


class InvestigationLead(BaseModel):
    lead_id: str
    category: LeadCategory
    action: str
    rationale: str
    evidence_reference: str
    priority: str = Field(default="HIGH", description="HIGH, MEDIUM, LOW")


class RecommendedAction(BaseModel):
    action_type: ActionCategory
    title: str
    description: str
    target_indicator: str
    urgency: str = Field(default="IMMEDIATE", description="IMMEDIATE, STANDARD, MONITOR")


class CorrelatedEntityFinding(BaseModel):
    relationship: str
    source_entity: str
    target_entity: str
    confidence: float = Field(default=0.9)
    evidence_details: str


class RelatedCase(BaseModel):
    investigation_id: str
    case_title: str
    relationship_type: str = Field(..., description="SAME_SUSPICIOUS_DOMAIN, SAME_ATTACHMENT_HASH, SAME_SOURCE_IP, etc.")
    confidence_label: str = Field(default="HIGH-CONFIDENCE MATCH", description="HIGH-CONFIDENCE MATCH, RELATED, POSSIBLE RELATIONSHIP")
    shared_indicator: str
    severity: str = Field(default="CRITICAL")


class AttackNarrativeStep(BaseModel):
    step_number: int
    phase: str
    title: str
    description: str
    evidence_excerpt: Optional[str] = None


class CorrelationResult(BaseModel):
    investigation_id: str
    evidence_id: str
    primary_pattern: ThreatPattern
    correlated_findings: List[CorrelatedEntityFinding] = Field(default_factory=list)
    entity_graph_summary: Dict[str, Any] = Field(default_factory=dict)
    related_cases: List[RelatedCase] = Field(default_factory=list)
    detected_patterns: List[ThreatPattern] = Field(default_factory=list)


class AIAnalystAssessment(BaseModel):
    assessment_id: str = Field(..., description="Unique AI assessment ID (e.g. AIA-2026-00001)")
    investigation_id: str
    evidence_id: str
    input_evidence_hash: str = Field(..., description="SHA-256 hash of evidence package analyzed")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    provider: str = Field(..., description="Google Gemini or Deterministic SOC Engine")
    model: str = Field(default="gemini-1.5-flash")
    fallback_used: bool = Field(default=False)
    fallback_reason: Optional[str] = None
    
    # Executive & Narrative
    executive_summary: str
    threat_pattern: ThreatPattern
    ai_confidence_score: float = Field(default=0.9, ge=0.0, le=1.0)
    ai_confidence_percentage: int = Field(default=90, ge=0, le=100)
    
    # Correlation & Attack Chain
    attack_narrative: List[AttackNarrativeStep] = Field(default_factory=list)
    correlated_findings: List[CorrelatedEntityFinding] = Field(default_factory=list)
    mitre_techniques: List[MITRETechnique] = Field(default_factory=list)
    investigation_leads: List[InvestigationLead] = Field(default_factory=list)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    related_cases: List[RelatedCase] = Field(default_factory=list)
    
    # Audit & Versioning
    output_version: str = Field(default="1.0")
    prompt_tokens: int = Field(default=0)


class ThreatVerdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    HIGH_RISK = "HIGH_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    LOW_RISK = "LOW_RISK"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


class EvidenceConfidence(str, Enum):
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class GapStatus(str, Enum):
    NOT_AVAILABLE = "NOT_AVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_CHECKED = "NOT_CHECKED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"


class EvidenceFinding(BaseModel):
    id: str
    category: str
    name: str
    description: str
    evidence: str
    severity: str
    weight: float
    confidence: EvidenceConfidence = EvidenceConfidence.HIGH
    source: str
    reason: str
    related_entity: Optional[str] = None


class ContradictionItem(BaseModel):
    id: str
    title: str
    description: str
    conflicting_elements: List[str] = Field(default_factory=list)
    severity: str = "HIGH"
    impact_on_assessment: str


class InvestigationGap(BaseModel):
    indicator_type: str
    status: GapStatus
    description: str
    impact: str


class EvidenceCategoryBreakdown(BaseModel):
    category: str
    raw_weight: float
    capped_weight: float
    indicators_count: int
    summary: str


class InvestigationAssessment(AIAnalystAssessment):
    """
    Phase 4 Automated Threat Analysis & Forensic Decision Engine Model.
    Provides explainable verdict, confidence rating, primary/supporting indicators,
    contradiction detection, gaps, attack chain, and inquiry questions.
    Maintains 100% backward compatibility with AIAnalystAssessment.
    """
    verdict: ThreatVerdict = Field(default=ThreatVerdict.SUSPICIOUS)
    confidence: EvidenceConfidence = Field(default=EvidenceConfidence.HIGH)
    severity: str = Field(default="MEDIUM")
    risk_score: int = Field(default=50, ge=0, le=100)
    threat_score: int = Field(default=50, ge=0, le=100)
    evidence_summary: str = Field(default="")
    primary_indicators: List[EvidenceFinding] = Field(default_factory=list)
    supporting_indicators: List[EvidenceFinding] = Field(default_factory=list)
    contradictions: List[ContradictionItem] = Field(default_factory=list)
    correlated_entities: List[CorrelatedEntityFinding] = Field(default_factory=list)
    attack_techniques: List[MITRETechnique] = Field(default_factory=list)
    attack_chain: List[AttackNarrativeStep] = Field(default_factory=list)
    suspicious_behaviors: List[str] = Field(default_factory=list)
    investigation_gaps: List[InvestigationGap] = Field(default_factory=list)
    analyst_questions: List[str] = Field(default_factory=list)
    category_breakdowns: List[EvidenceCategoryBreakdown] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    engine_version: str = Field(default="4.0")
