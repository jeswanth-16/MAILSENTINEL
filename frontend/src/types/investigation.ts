export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';

export type CaseStatus =
  | 'NEW'
  | 'TRIAGING'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'CLOSED'
  | 'FALSE_POSITIVE'
  | 'OPEN'
  | 'IN_REVIEW';

export type ThreatClassification =
  | 'PHISHING'
  | 'BUSINESS_EMAIL_COMPROMISE'
  | 'FINANCIAL_FRAUD'
  | 'CREDENTIAL_HARVESTING'
  | 'MALICIOUS_ATTACHMENT'
  | 'MALWARE'
  | 'SUSPICIOUS'
  | 'BENIGN'
  | 'IMPERSONATION'
  | 'UNKNOWN';

export type PriorityLevel = 'P1_CRITICAL' | 'P2_HIGH' | 'P3_MEDIUM' | 'P4_LOW';

export type NoteType = 'NOTE' | 'ACTION' | 'DECISION' | 'ESCALATION' | 'SYSTEM';

export interface AnalystNote {
  note_id: string;
  investigation_id: string;
  author: string;
  timestamp: string;
  content: string;
  note_type: NoteType;
}

export interface InvestigationSummary {
  id: string;
  case_number?: string;
  title: string;
  sender: string;
  subject: string;
  severity: ThreatSeverity;
  threat_score: number;
  risk_score?: number;
  classification?: string;
  confidence?: number;
  status: string;
  analyst: string;
  assigned_analyst?: string;
  priority?: string;
  tags?: string[];
  evidence_hash: string;
  blockchain_verified: boolean;
  blockchain_status?: string;
  created_at: string;
  updated_at: string;
}

export interface Investigation {
  id: string;
  case_number: string;
  title: string;
  description: string;
  source: string;
  created_at: string;
  updated_at: string;
  status: string;
  severity: ThreatSeverity;
  classification: string;
  risk_score: number;
  threat_score?: number;
  confidence: number;
  assigned_analyst: string;
  analyst?: string;
  tags: string[];
  priority: PriorityLevel;
  email_evidence_id?: string;
  evidence_id?: string;
  evidence_hash: string;
  sender: string;
  subject: string;
  blockchain_status: string;
  blockchain_tx?: string;
  blockchain_block?: number;
  blockchain_network?: string;
  blockchain_verified: boolean;
  created_by: string;
  notes: AnalystNote[];
  verdict_summary?: string;
  recommended_actions: string[];
}

export interface InvestigationListResponse {
  total: number;
  investigations: InvestigationSummary[];
}

export interface InvestigationOverview {
  investigation: Investigation;
  top_indicators: Array<{
    name: string;
    category: string;
    severity: string;
    score_impact: number;
    description: string;
    evidence_excerpt: string;
  }>;
  top_entities: {
    ips_count: number;
    domains_count: number;
    urls_count: number;
    attachments_count: number;
    suspicious_domains: string[];
    suspicious_urls: string[];
    attachments: string[];
  };
  auth_summary: {
    spf?: string;
    dkim?: string;
    dmarc?: string;
  };
  key_findings: string[];
  blockchain_summary: {
    status: string;
    verified: boolean;
    evidence_id?: string;
    evidence_hash?: string;
    transaction_hash?: string;
    block_number?: number;
    network?: string;
  };
  latest_activity: Array<{
    timestamp: string;
    author: string;
    type: string;
    content: string;
  }>;
}

export interface DashboardStats {
  total_investigations: number;
  critical_cases: number;
  high_cases: number;
  medium_cases: number;
  low_clean_cases: number;
  cases_today: number;
  blockchain_verified_count: number;
  blockchain_verified_percentage: number;
  tamper_alerts: number;
  mean_latency_seconds: number;
  classification_breakdown: Record<string, number>;
  status_breakdown: Record<string, number>;
  top_source_ips: Array<{
    ip: string;
    count: number;
    country: string;
    threat: string;
  }>;
  top_domains: Array<{
    domain: string;
    count: number;
    type: string;
    risk: string;
  }>;
  top_countries: Array<{
    country_code: string;
    country_name: string;
    incidents: number;
    percentage: number;
  }>;
}

export interface RunFullInvestigationResult {
  investigation: Investigation;
  steps_completed: string[];
  verdict: {
    classification: string;
    severity: string;
    risk_score: number;
    confidence: number;
    evidence_hash: string;
    blockchain_block?: number;
    blockchain_tx?: string;
    integrity_verified: boolean;
  };
}

export interface InvestigationReportData {
  case: Investigation;
  forensic_summary: any;
  threat_assessment: any;
  intelligence_summary: any;
  timeline_events: any[];
  custody_chain: any[];
  exported_at: string;
  report_id: string;
}
