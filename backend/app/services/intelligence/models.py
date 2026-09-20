from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class IPCategory(str, Enum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    DOCUMENTATION_TEST = "DOCUMENTATION_TEST"
    RESERVED = "RESERVED"
    MULTICAST = "MULTICAST"
    INVALID = "INVALID"


class ReputationStatus(str, Enum):
    KNOWN_MALICIOUS = "KNOWN_MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class LookupStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PRIVATE_IP_SKIPPED = "PRIVATE_IP_SKIPPED"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class IPIntelligenceResult(BaseModel):
    entity_id: str = Field(..., description="Stable entity identifier e.g. ip:185.220.101.5")
    ip: str = Field(..., description="IPv4 or IPv6 address")
    category: IPCategory = Field(default=IPCategory.PUBLIC)
    is_routable: bool = Field(default=True)
    country: Optional[str] = Field(default=None, description="Observed country name")
    country_code: Optional[str] = Field(default=None, description="2-letter ISO country code")
    region: Optional[str] = Field(default=None)
    city: Optional[str] = Field(default=None)
    latitude: Optional[float] = Field(default=None)
    longitude: Optional[float] = Field(default=None)
    asn: Optional[str] = Field(default=None, description="Autonomous System Number e.g. AS208323")
    organization: Optional[str] = Field(default=None, description="Network / ASN Org name")
    isp: Optional[str] = Field(default=None)
    timezone: Optional[str] = Field(default=None)
    reputation: ReputationStatus = Field(default=ReputationStatus.UNKNOWN)
    source: str = Field(default="intelligence_service")
    status: LookupStatus = Field(default=LookupStatus.NOT_AVAILABLE)
    status_message: Optional[str] = Field(default=None)
    cached: bool = Field(default=False, description="Whether the result was served from intelligence cache")
    attribution: Optional[str] = Field(default=None, description="Delivery status: REAL-TIME, OFFLINE FALLBACK, CACHED, or UNAVAILABLE")
    abuse_confidence_score: Optional[int] = Field(default=None, description="Abuse confidence score (0-100) from provider")
    total_reports: Optional[int] = Field(default=None, description="Total abuse reports from provider")
    last_reported_at: Optional[str] = Field(default=None, description="Last reported activity timestamp")
    usage_type: Optional[str] = Field(default=None, description="Observed network usage type")
    domain: Optional[str] = Field(default=None, description="Associated domain from provider")
    looked_up_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DomainIntelligenceResult(BaseModel):
    entity_id: str = Field(..., description="Stable entity identifier e.g. domain:paypa1-security.com")
    domain: str = Field(..., description="Raw extracted domain")
    normalized_domain: str = Field(...)
    registrable_domain: Optional[str] = Field(default=None)
    tld: str = Field(default="")
    subdomain_depth: int = Field(default=0)
    is_punycode: bool = Field(default=False)
    punycode_decoded: Optional[str] = Field(default=None)
    is_internal: bool = Field(default=False)
    is_localhost: bool = Field(default=False)
    dns_status: LookupStatus = Field(default=LookupStatus.NOT_AVAILABLE)
    a_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    registrar: Optional[str] = Field(default=None)
    created_at: Optional[str] = Field(default=None)
    expires_at: Optional[str] = Field(default=None)
    nameservers: List[str] = Field(default_factory=list)
    structural_indicators: List[str] = Field(default_factory=list)
    reputation: ReputationStatus = Field(default=ReputationStatus.UNKNOWN)
    source: str = Field(default="intelligence_service")
    status: LookupStatus = Field(default=LookupStatus.SUCCESS)
    status_message: Optional[str] = Field(default=None)
    cached: bool = Field(default=False)
    attribution: Optional[str] = Field(default="LOCAL ANALYSIS")
    is_lookalike: bool = Field(default=False)
    is_lookalike_brand: bool = Field(default=False)
    looked_up_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __init__(self, **data: Any):
        if "is_lookalike" in data and "is_lookalike_brand" not in data:
            data["is_lookalike_brand"] = data["is_lookalike"]
        elif "is_lookalike_brand" in data and "is_lookalike" not in data:
            data["is_lookalike"] = data["is_lookalike_brand"]
        super().__init__(**data)


class URLIntelligenceResult(BaseModel):
    entity_id: str = Field(..., description="Stable entity identifier e.g. url:https://example.com/auth")
    url: str = Field(..., description="Raw extracted URL")
    normalized_url: str = Field(...)
    domain: str = Field(...)
    hostname: Optional[str] = Field(default=None)
    host_ip: Optional[str] = Field(default=None)
    scheme: str = Field(default="http")
    port: Optional[int] = Field(default=None)
    path: str = Field(default="")
    query: str = Field(default="")
    has_query: bool = Field(default=False)
    is_ip_host: bool = Field(default=False)
    has_credential_path: bool = Field(default=False)
    has_credential_keywords: bool = Field(default=False)
    is_punycode: bool = Field(default=False)
    structural_indicators: List[str] = Field(default_factory=list)
    reputation: ReputationStatus = Field(default=ReputationStatus.UNKNOWN)
    source: str = Field(default="intelligence_service")
    status: LookupStatus = Field(default=LookupStatus.SUCCESS)
    status_message: Optional[str] = Field(default=None)
    cached: bool = Field(default=False)
    attribution: Optional[str] = Field(default="LOCAL ANALYSIS")
    looked_up_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __init__(self, **data: Any):
        if "has_credential_path" in data and "has_credential_keywords" not in data:
            data["has_credential_keywords"] = data["has_credential_path"]
        elif "has_credential_keywords" in data and "has_credential_path" not in data:
            data["has_credential_path"] = data["has_credential_keywords"]
        super().__init__(**data)


class EmailRole(str, Enum):
    SENDER = "SENDER"
    REPLY_TO = "REPLY_TO"
    RETURN_PATH = "RETURN_PATH"
    RECIPIENT = "RECIPIENT"
    CC = "CC"
    BCC = "BCC"


class EmailAddressIntelligenceResult(BaseModel):
    entity_id: str = Field(..., description="Stable entity identifier e.g. email:user@example.com")
    raw_email: str = Field(...)
    normalized_email: str = Field(...)
    local_part: str = Field(...)
    domain: str = Field(...)
    role: EmailRole = Field(default=EmailRole.SENDER)
    is_valid_syntax: bool = Field(default=True)
    is_disposable_domain: bool = Field(default=False)
    is_disposable: bool = Field(default=False)
    is_free_provider: bool = Field(default=False)
    is_lookalike_domain: bool = Field(default=False)
    raw_address: Optional[str] = None
    normalized_address: Optional[str] = None
    reputation: ReputationStatus = Field(default=ReputationStatus.UNKNOWN)
    source: str = Field(default="email_analyzer")
    status: LookupStatus = Field(default=LookupStatus.SUCCESS)
    attribution: Optional[str] = Field(default="LOCAL ANALYSIS")
    cached: bool = Field(default=False)
    status_message: Optional[str] = Field(default=None)
    looked_up_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __init__(self, **data: Any):
        if "raw_email" in data and "raw_address" not in data:
            data["raw_address"] = data["raw_email"]
        elif "raw_address" in data and "raw_email" not in data:
            data["raw_email"] = data["raw_address"]

        if "normalized_email" in data and "normalized_address" not in data:
            data["normalized_address"] = data["normalized_email"]
        elif "normalized_address" in data and "normalized_email" not in data:
            data["normalized_email"] = data["normalized_address"]

        if "is_disposable_domain" in data and "is_disposable" not in data:
            data["is_disposable"] = data["is_disposable_domain"]
        elif "is_disposable" in data and "is_disposable_domain" not in data:
            data["is_disposable_domain"] = data["is_disposable"]

        super().__init__(**data)


class InvestigationIntelligenceSummary(BaseModel):
    entities_analyzed: int = Field(default=0)
    successful_lookups: int = Field(default=0)
    private_skipped: int = Field(default=0)
    unknown_or_unavailable: int = Field(default=0)


class InvestigationIntelligenceResult(BaseModel):
    investigation_id: str
    ips: List[IPIntelligenceResult] = Field(default_factory=list)
    domains: List[DomainIntelligenceResult] = Field(default_factory=list)
    urls: List[URLIntelligenceResult] = Field(default_factory=list)
    emails: List[EmailAddressIntelligenceResult] = Field(default_factory=list)
    summary: InvestigationIntelligenceSummary
    enriched_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
