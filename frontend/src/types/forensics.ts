export type TimelineEventType =
  | 'EMAIL_CREATED'
  | 'EMAIL_RECEIVED'
  | 'SMTP_RELAY'
  | 'AUTHENTICATION_CHECK'
  | 'URL_DISCOVERED'
  | 'DOMAIN_DISCOVERED'
  | 'IP_DISCOVERED'
  | 'ATTACHMENT_DISCOVERED'
  | 'THREAT_INDICATOR'
  | 'INTELLIGENCE_LOOKUP'
  | 'GEOLOCATION_RESOLVED'
  | 'RISK_ASSESSMENT'
  | 'EVIDENCE_HASHED';

export type TimestampPrecision = 'SECOND' | 'MINUTE' | 'HOUR' | 'DAY' | 'UNKNOWN';

export interface TimelineEvent {
  event_id: string;
  investigation_id: string;
  timestamp?: string | null;
  timestamp_precision: TimestampPrecision;
  event_type: TimelineEventType;
  title: string;
  description: string;
  source: string;
  entity_type?: string | null;
  entity_id?: string | null;
  severity?: string | null;
  evidence_reference?: string | null;
  metadata?: Record<string, any>;
}

export interface TimelineResponse {
  investigation_id: string;
  events: TimelineEvent[];
  total_events: number;
}

export type GraphNodeType =
  | 'EMAIL'
  | 'IP'
  | 'DOMAIN'
  | 'URL'
  | 'ATTACHMENT'
  | 'THREAT_INDICATOR'
  | 'ASN'
  | 'ORGANIZATION'
  | 'LOCATION'
  | 'INVESTIGATION';

export type GraphEdgeType =
  | 'SENT_FROM'
  | 'RECEIVED_BY'
  | 'RELAYED_THROUGH'
  | 'RESOLVES_TO'
  | 'CONTAINS_URL'
  | 'CONTAINS_ATTACHMENT'
  | 'TRIGGERS'
  | 'ASSOCIATED_WITH'
  | 'GEOLOCATED_AT'
  | 'BELONGS_TO_ASN'
  | 'BELONGS_TO_ORGANIZATION'
  | 'OBSERVED_IN';

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  severity: string;
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: GraphEdgeType;
  confidence: number;
  evidence_reference?: string | null;
}

export interface AttackGraphResponse {
  investigation_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_nodes: number;
  total_edges: number;
}
