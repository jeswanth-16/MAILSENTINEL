export type ThreatSeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';

export type ThreatClassification =
  | 'BENIGN'
  | 'SUSPICIOUS'
  | 'PHISHING'
  | 'CREDENTIAL_HARVESTING'
  | 'BUSINESS_EMAIL_COMPROMISE'
  | 'FINANCIAL_FRAUD'
  | 'MALICIOUS_ATTACHMENT'
  | 'IMPERSONATION'
  | 'UNKNOWN';

export interface ThreatIndicator {
  id: string;
  category: string;
  name: string;
  description: string;
  evidence: string;
  severity: ThreatSeverityLevel;
  weight: number;
  confidence: number;
  source: string;
}

export interface CategoryScoreBreakdown {
  category: string;
  raw_points: number;
  capped_points: number;
  max_cap: number;
  indicator_count: number;
}

export interface ExplanationItem {
  indicator_id: string;
  category: string;
  title: string;
  evidence: string;
  score_contribution: number;
  confidence: number;
  rationale: string;
}

export interface RecommendationItem {
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  action: string;
  guidance: string;
}

export interface AIAnalysisResult {
  available: boolean;
  provider: string;
  suggested_classification?: string;
  confidence: number;
  social_engineering_signals: string[];
  reasoning: string[];
  status_message: string;
}

export interface ThreatAssessmentResult {
  investigation_id: string;
  risk_score: number;
  severity: ThreatSeverityLevel;
  classification: ThreatClassification;
  confidence: number;
  confidence_percentage: number;
  summary: string;
  indicators: ThreatIndicator[];
  category_breakdown: CategoryScoreBreakdown[];
  explanations: ExplanationItem[];
  recommendations: RecommendationItem[];
  ai_enrichment: AIAnalysisResult;
  evaluated_at: string;
}
