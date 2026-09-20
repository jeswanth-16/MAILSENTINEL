export type ReportType =
  | 'EXECUTIVE'
  | 'FORENSIC'
  | 'INCIDENT_RESPONSE'
  | 'FULL_INVESTIGATION';

export type ReportStatus = 'GENERATED' | 'VERIFIED' | 'TAMPER_DETECTED' | 'ARCHIVED';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingCategory =
  | 'AUTHENTICATION'
  | 'DOMAIN_REPUTATION'
  | 'URL_ANALYSIS'
  | 'ATTACHMENT'
  | 'ANOMALY'
  | 'BEHAVIORAL'
  | 'NETWORK';

export interface ReportFinding {
  finding_id: string;
  title: string;
  severity: FindingSeverity;
  category: FindingCategory;
  description: string;
  evidence_reference: string;
  confidence: number;
  impact: string;
  recommendation: string;
}

export interface ReportEvidenceReference {
  reference_id: string;
  evidence_type: string;
  description: string;
  sha256?: string;
  source_locator: string;
  metadata?: Record<string, any>;
}

export interface ReportRecommendation {
  recommendation_id: string;
  priority: string;
  category: string;
  title: string;
  action: string;
  rationale: string;
}

export interface ReportSignature {
  signer_name: string;
  role: string;
  timestamp: string;
  signature_hash: string;
  signature_algorithm: string;
}

export interface ReportMetadata {
  report_id: string;
  case_id: string;
  investigation_id?: string;
  generated_at: string;
  generated_by: string;
  report_type: ReportType;
  classification: string;
  severity: string;
  risk_score: number;
  version: string;
  evidence_sha256: string;
  blockchain_status: string;
  blockchain_tx_hash?: string;
  blockchain_block_number?: number;
  report_sha256?: string;
}

export interface ForensicReport {
  metadata: ReportMetadata;
  executive_summary: Record<string, any>;
  case_info: Record<string, any>;
  evidence_info: Record<string, any>;
  email_metadata: Record<string, any>;
  header_analysis: Record<string, any>;
  auth_analysis: Record<string, any>;
  mail_route: Array<Record<string, any>>;
  ip_intelligence: Array<Record<string, any>>;
  domain_intelligence: Array<Record<string, any>>;
  url_analysis: Array<Record<string, any>>;
  attachment_analysis: Array<Record<string, any>>;
  threat_indicators: Array<Record<string, any>>;
  risk_assessment: Record<string, any>;
  attack_timeline: Array<Record<string, any>>;
  attack_graph_summary: Record<string, any>;
  ai_assessment: Record<string, any>;
  mitre_tactics: string[];
  mitre_techniques: string[];
  correlated_entities: Array<Record<string, any>>;
  response_actions: Array<Record<string, any>>;
  analyst_notes: Array<Record<string, any>>;
  custody_chain: Array<Record<string, any>>;
  blockchain_integrity: Record<string, any>;
  evidence_references: ReportEvidenceReference[];
  findings: ReportFinding[];
  recommendations: ReportRecommendation[];
  conclusion: string;
  signatures: ReportSignature[];
}

export interface ReportManifest {
  package_id: string;
  created_at: string;
  case_id: string;
  investigation_id?: string;
  files: string[];
  file_sha256: Record<string, string>;
  original_evidence_sha256: string;
  blockchain_anchor_reference?: string;
  package_sha256?: string;
}

export interface GenerateReportRequest {
  report_type?: ReportType;
  generated_by?: string;
  include_ai_assessment?: boolean;
}

export interface VerifyReportResponse {
  report_id: string;
  status: ReportStatus;
  stored_hash: string;
  calculated_hash: string;
  verified: boolean;
  tamper_detected: boolean;
  message: string;
  verification_timestamp: string;
}
