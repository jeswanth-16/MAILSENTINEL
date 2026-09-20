from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    AUTHENTICATION = "Authentication"
    SENDER = "Sender"
    URL = "URL"
    DOMAIN = "Domain"
    SOCIAL_ENGINEERING = "Social Engineering"
    ATTACHMENT = "Attachment"
    HEADER_ROUTE = "Header & Route"
    CORRELATION = "Correlation"


class ThreatSeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


class ThreatClassification(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    BUSINESS_EMAIL_COMPROMISE = "BUSINESS_EMAIL_COMPROMISE"
    FINANCIAL_FRAUD = "FINANCIAL_FRAUD"
    MALICIOUS_ATTACHMENT = "MALICIOUS_ATTACHMENT"
    IMPERSONATION = "IMPERSONATION"
    UNKNOWN = "UNKNOWN"


class ThreatIndicator(BaseModel):
    id: str = Field(..., description="Unique indicator identifier e.g. AUTH_SPF_FAIL")
    category: ThreatCategory = Field(..., description="Indicator category")
    name: str = Field(..., description="Human readable indicator name")
    description: str = Field(..., description="Technical explanation of the indicator")
    evidence: str = Field(..., description="Exact observable evidence extracted from email")
    severity: ThreatSeverityLevel = Field(..., description="Severity of this specific indicator")
    weight: float = Field(..., ge=0, description="Base risk score contribution weight")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection certainty (0.0 - 1.0)")
    source: str = Field(default="email_forensics", description="Source of indicator")


class AIAnalysisResult(BaseModel):
    available: bool = Field(default=False, description="Whether AI enrichment was active")
    provider: str = Field(default="none", description="AI provider used")
    suggested_classification: Optional[str] = Field(default=None)
    confidence: float = Field(default=0.0)
    social_engineering_signals: List[str] = Field(default_factory=list)
    reasoning: List[str] = Field(default_factory=list)
    status_message: str = Field(default="AI enrichment unavailable — deterministic analysis used.")
