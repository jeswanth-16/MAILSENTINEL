export type IPCategory =
  | 'PUBLIC'
  | 'PRIVATE'
  | 'LOOPBACK'
  | 'LINK_LOCAL'
  | 'DOCUMENTATION_TEST'
  | 'RESERVED'
  | 'MULTICAST'
  | 'INVALID';

export type ReputationStatus =
  | 'KNOWN_MALICIOUS'
  | 'SUSPICIOUS'
  | 'CLEAN'
  | 'UNKNOWN'
  | 'NOT_AVAILABLE';

export type LookupStatus =
  | 'SUCCESS'
  | 'PRIVATE_IP_SKIPPED'
  | 'NOT_AVAILABLE'
  | 'PROVIDER_UNAVAILABLE'
  | 'TIMEOUT'
  | 'ERROR';

export interface IPIntelligenceResult {
  entity_id: string;
  ip: string;
  category: IPCategory;
  is_routable: boolean;
  country?: string | null;
  country_code?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  asn?: string | null;
  organization?: string | null;
  isp?: string | null;
  timezone?: string | null;
  reputation: ReputationStatus;
  source: string;
  status: LookupStatus;
  status_message?: string | null;
  cached?: boolean;
  attribution?: string | null;
  abuse_confidence_score?: number | null;
  total_reports?: number | null;
  last_reported_at?: string | null;
  usage_type?: string | null;
  domain?: string | null;
  looked_up_at: string;
}

export interface DomainIntelligenceResult {
  entity_id: string;
  domain: string;
  normalized_domain: string;
  registrable_domain?: string | null;
  tld: string;
  subdomain_depth: number;
  is_punycode: boolean;
  punycode_decoded?: string | null;
  is_internal?: boolean;
  is_localhost?: boolean;
  is_lookalike?: boolean;
  is_lookalike_brand?: boolean;
  dns_status: LookupStatus;
  a_records: string[];
  mx_records: string[];
  ns_records: string[];
  txt_records: string[];
  structural_indicators: string[];
  reputation: ReputationStatus;
  source: string;
  status: LookupStatus;
  status_message?: string | null;
  cached?: boolean;
  attribution?: string | null;
  looked_up_at: string;
}

export interface URLIntelligenceResult {
  entity_id: string;
  url: string;
  normalized_url: string;
  domain: string;
  hostname?: string | null;
  host_ip?: string | null;
  scheme: string;
  port?: number | null;
  path: string;
  query: string;
  has_query?: boolean;
  is_ip_host: boolean;
  has_credential_path: boolean;
  has_credential_keywords?: boolean;
  is_punycode: boolean;
  structural_indicators: string[];
  reputation: ReputationStatus;
  source: string;
  status: LookupStatus;
  status_message?: string | null;
  cached?: boolean;
  attribution?: string | null;
  looked_up_at: string;
}

export type EmailRole =
  | 'SENDER'
  | 'REPLY_TO'
  | 'RETURN_PATH'
  | 'RECIPIENT'
  | 'CC'
  | 'BCC';

export interface EmailAddressIntelligenceResult {
  entity_id: string;
  raw_email: string;
  normalized_email: string;
  raw_address?: string;
  normalized_address?: string;
  local_part: string;
  domain: string;
  role: EmailRole;
  is_valid_syntax: boolean;
  is_disposable_domain: boolean;
  is_disposable?: boolean;
  is_free_provider: boolean;
  is_lookalike_domain?: boolean;
  reputation: ReputationStatus;
  source: string;
  status: LookupStatus;
  attribution?: string | null;
  cached?: boolean;
  status_message?: string | null;
  looked_up_at: string;
}

export interface InvestigationIntelligenceSummary {
  entities_analyzed: number;
  successful_lookups: number;
  private_skipped: number;
  unknown_or_unavailable: number;
}

export interface InvestigationIntelligenceResult {
  investigation_id: string;
  ips: IPIntelligenceResult[];
  domains: DomainIntelligenceResult[];
  urls: URLIntelligenceResult[];
  emails?: EmailAddressIntelligenceResult[];
  summary: InvestigationIntelligenceSummary;
  enriched_at: string;
}

export interface CorrelationRelationship {
  source: string;
  source_type: string;
  target: string;
  target_type: string;
  relationship: string;
  evidence: string;
  confidence: number;
}

export interface CorrelationThreatSignal {
  signal_id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  weight: number;
  entities_involved: string[];
}

export interface CorrelationSummary {
  total_indicators: number;
  total_relationships: number;
  total_signals: number;
  mismatches_detected: number;
  infrastructure_overlap: number;
}

export interface IndicatorCorrelationResult {
  investigation_id: string;
  emails: EmailAddressIntelligenceResult[];
  domains: DomainIntelligenceResult[];
  urls: URLIntelligenceResult[];
  ips: IPIntelligenceResult[];
  relationships: CorrelationRelationship[];
  signals: CorrelationThreatSignal[];
  summary: CorrelationSummary;
  correlated_at: string;
}

export interface IndicatorCorrelationRequest {
  investigation_id?: string;
  emails?: string[];
  domains?: string[];
  urls?: string[];
  ips?: string[];
}
