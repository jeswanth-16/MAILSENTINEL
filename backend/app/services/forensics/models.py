from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TimelineEventType(str, Enum):
    EMAIL_CREATED = "EMAIL_CREATED"
    EMAIL_RECEIVED = "EMAIL_RECEIVED"
    SMTP_RELAY = "SMTP_RELAY"
    AUTHENTICATION_CHECK = "AUTHENTICATION_CHECK"
    URL_DISCOVERED = "URL_DISCOVERED"
    DOMAIN_DISCOVERED = "DOMAIN_DISCOVERED"
    IP_DISCOVERED = "IP_DISCOVERED"
    ATTACHMENT_DISCOVERED = "ATTACHMENT_DISCOVERED"
    THREAT_INDICATOR = "THREAT_INDICATOR"
    INTELLIGENCE_LOOKUP = "INTELLIGENCE_LOOKUP"
    GEOLOCATION_RESOLVED = "GEOLOCATION_RESOLVED"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    EVIDENCE_HASHED = "EVIDENCE_HASHED"


class TimestampPrecision(str, Enum):
    SECOND = "SECOND"
    MINUTE = "MINUTE"
    HOUR = "HOUR"
    DAY = "DAY"
    UNKNOWN = "UNKNOWN"


class TimelineEvent(BaseModel):
    event_id: str = Field(..., description="Unique event identifier e.g. evt-001")
    investigation_id: str = Field(..., description="Associated investigation ID")
    timestamp: Optional[str] = Field(default=None, description="ISO timestamp or trustworthy header time; None if unavailable")
    timestamp_precision: TimestampPrecision = Field(default=TimestampPrecision.UNKNOWN)
    event_type: TimelineEventType = Field(...)
    title: str = Field(...)
    description: str = Field(...)
    source: str = Field(...)
    entity_type: Optional[str] = Field(default=None, description="EMAIL, IP, DOMAIN, URL, ATTACHMENT, INDICATOR, ASSESSMENT")
    entity_id: Optional[str] = Field(default=None)
    severity: Optional[str] = Field(default="INFO", description="CRITICAL, HIGH, MEDIUM, LOW, CLEAN, INFO")
    evidence_reference: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TimelineResponse(BaseModel):
    investigation_id: str
    events: List[TimelineEvent] = Field(default_factory=list)
    total_events: int = Field(default=0)


class GraphNodeType(str, Enum):
    EMAIL = "EMAIL"
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    ATTACHMENT = "ATTACHMENT"
    THREAT_INDICATOR = "THREAT_INDICATOR"
    ASN = "ASN"
    ORGANIZATION = "ORGANIZATION"
    LOCATION = "LOCATION"
    INVESTIGATION = "INVESTIGATION"


class GraphEdgeType(str, Enum):
    SENT_FROM = "SENT_FROM"
    RECEIVED_BY = "RECEIVED_BY"
    RELAYED_THROUGH = "RELAYED_THROUGH"
    RESOLVES_TO = "RESOLVES_TO"
    CONTAINS_URL = "CONTAINS_URL"
    CONTAINS_ATTACHMENT = "CONTAINS_ATTACHMENT"
    TRIGGERS = "TRIGGERS"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    GEOLOCATED_AT = "GEOLOCATED_AT"
    BELONGS_TO_ASN = "BELONGS_TO_ASN"
    BELONGS_TO_ORGANIZATION = "BELONGS_TO_ORGANIZATION"
    OBSERVED_IN = "OBSERVED_IN"
    HOSTED_ON = "HOSTED_ON"
    REPLY_TO = "REPLY_TO"
    ATTACHED_TO = "ATTACHED_TO"
    INVOLVED_IN = "INVOLVED_IN"
    BELONGS_TO_DOMAIN = "BELONGS_TO_DOMAIN"
    REFERENCES = "REFERENCES"


class GraphNode(BaseModel):
    id: str = Field(..., description="Unique node ID e.g. ip:185.220.101.5")
    type: GraphNodeType = Field(...)
    label: str = Field(...)
    severity: str = Field(default="INFO", description="CRITICAL, HIGH, MEDIUM, LOW, CLEAN, INFO")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str = Field(..., description="Unique edge ID e.g. edge-email-ip-001")
    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    type: GraphEdgeType = Field(...)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Certainty score of relationship (1.0 = direct evidence)")
    evidence_reference: Optional[str] = Field(default=None)


class AttackGraphResponse(BaseModel):
    investigation_id: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    total_nodes: int = Field(default=0)
    total_edges: int = Field(default=0)
