export type ThreatPatternType =
  | 'BUSINESS_EMAIL_COMPROMISE'
  | 'CREDENTIAL_HARVESTING'
  | 'MALICIOUS_ATTACHMENT'
  | 'FINANCIAL_FRAUD'
  | 'RECONNAISSANCE_PHISHING'
  | 'SUPPLY_CHAIN_IMPERSONATION'
  | 'BENIGN'
  | 'UNKNOWN';

export type MITRETactic =
  | 'Initial Access'
  | 'Execution'
  | 'Persistence'
  | 'Credential Access'
  | 'Discovery'
  | 'Lateral Movement'
  | 'Collection'
  | 'Command and Control'
  | 'Exfiltration'
  | 'Impact';

export type ConfidenceRating = 'HIGH' | 'MEDIUM' | 'LOW' | 'NOT_CONFIRMED';

export type LeadCategory =
  | 'MAIL_GATEWAY'
  | 'ENDPOINT_TELEMETRY'
  | 'PROXY_LOGS'
  | 'COMMUNICATION_VERIFICATION'
  | 'DNS_ANALYSIS'
  | 'IDENTITY_ACCESS';

export type ActionCategory = 'CONTAIN' | 'INVESTIGATE' | 'BLOCK' | 'PRESERVE' | 'NOTIFY';

export type ThreatVerdict =
  | 'MALICIOUS'
  | 'HIGH_RISK'
  | 'SUSPICIOUS'
  | 'LOW_RISK'
  | 'BENIGN'
  | 'UNKNOWN';

export type EvidenceConfidence = 'VERY_HIGH' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export type GapStatus =
  | 'NOT_AVAILABLE'
  | 'NOT_APPLICABLE'
  | 'NOT_CHECKED'
  | 'PROVIDER_UNAVAILABLE';

export interface EvidenceFinding {
  id: string;
  category: string;
  name: string;
  description: string;
  evidence: string;
  severity: string;
  weight: number;
  confidence: EvidenceConfidence;
  source: string;
  reason: string;
  related_entity?: string;
}

export interface ContradictionItem {
  id: string;
  title: string;
  description: string;
  conflicting_elements: string[];
  severity: string;
  impact_on_assessment: string;
}

export interface InvestigationGap {
  indicator_type: string;
  status: GapStatus;
  description: string;
  impact: string;
}

export interface EvidenceCategoryBreakdown {
  category: string;
  raw_weight: number;
  capped_weight: number;
  indicators_count: number;
  summary: string;
}

export interface MITRETechnique {
  technique_id: string;
  name: string;
  tactic: MITRETactic;
  rationale: string;
  evidence: string;
  confidence: ConfidenceRating;
}

export interface ThreatPattern {
  pattern_type: ThreatPatternType;
  title: string;
  confidence: number;
  confidence_percentage: number;
  description: string;
  indicators_involved: string[];
}

export interface InvestigationLead {
  lead_id: string;
  category: LeadCategory;
  action: string;
  rationale: string;
  evidence_reference: string;
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface RecommendedAction {
  action_type: ActionCategory;
  title: string;
  description: string;
  target_indicator: string;
  urgency: 'IMMEDIATE' | 'STANDARD' | 'MONITOR';
}

export interface CorrelatedEntityFinding {
  relationship: string;
  source_entity: string;
  target_entity: string;
  confidence: number;
  evidence_details: string;
}

export interface RelatedCase {
  investigation_id: string;
  case_title: string;
  relationship_type: string;
  confidence_label: string;
  shared_indicator: string;
  severity: string;
}

export interface AttackNarrativeStep {
  step_number: number;
  phase: string;
  title: string;
  description: string;
  evidence_excerpt?: string;
}

export interface CorrelationResult {
  investigation_id: string;
  evidence_id: string;
  primary_pattern: ThreatPattern;
  correlated_findings: CorrelatedEntityFinding[];
  entity_graph_summary: Record<string, any>;
  related_cases: RelatedCase[];
  detected_patterns: ThreatPattern[];
}

export interface AIAnalystAssessment {
  assessment_id: string;
  investigation_id: string;
  evidence_id: string;
  input_evidence_hash: string;
  created_at: string;
  provider: string;
  model: string;
  fallback_used: boolean;
  fallback_reason?: string;
  executive_summary: string;
  threat_pattern: ThreatPattern;
  ai_confidence_score: number;
  ai_confidence_percentage: number;
  attack_narrative: AttackNarrativeStep[];
  correlated_findings: CorrelatedEntityFinding[];
  mitre_techniques: MITRETechnique[];
  investigation_leads: InvestigationLead[];
  recommended_actions: RecommendedAction[];
  related_cases: RelatedCase[];
  output_version: string;
  prompt_tokens: number;

  // Phase 4 Extensions (optional for compatibility)
  verdict?: ThreatVerdict;
  confidence?: EvidenceConfidence;
  severity?: string;
  risk_score?: number;
  threat_score?: number;
  evidence_summary?: string;
  primary_indicators?: EvidenceFinding[];
  supporting_indicators?: EvidenceFinding[];
  contradictions?: ContradictionItem[];
  correlated_entities?: CorrelatedEntityFinding[];
  attack_techniques?: MITRETechnique[];
  attack_chain?: AttackNarrativeStep[];
  suspicious_behaviors?: string[];
  investigation_gaps?: InvestigationGap[];
  analyst_questions?: string[];
  category_breakdowns?: EvidenceCategoryBreakdown[];
  generated_at?: string;
  engine_version?: string;
}

export type InvestigationAssessment = AIAnalystAssessment;
