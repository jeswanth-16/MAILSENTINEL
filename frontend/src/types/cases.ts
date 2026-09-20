export type CaseStatus =
  | 'NEW'
  | 'TRIAGING'
  | 'INVESTIGATING'
  | 'CONTAINMENT'
  | 'ERADICATION'
  | 'RECOVERY'
  | 'MONITORING'
  | 'RESOLVED'
  | 'CLOSED';

export type CasePriority = 'P1_CRITICAL' | 'P2_HIGH' | 'P3_MEDIUM' | 'P4_LOW';

export type IncidentVerdict =
  | 'MALICIOUS'
  | 'HIGH_RISK'
  | 'SUSPICIOUS'
  | 'LOW_RISK'
  | 'BENIGN'
  | 'UNKNOWN'
  | 'FALSE_POSITIVE'
  | 'INCONCLUSIVE';

export type NoteCategory =
  | 'OBSERVATION'
  | 'ANALYSIS'
  | 'DECISION'
  | 'CONTAINMENT'
  | 'EVIDENCE'
  | 'COMMUNICATION'
  | 'HANDOFF';

export type ActionType =
  | 'CONTAIN'
  | 'BLOCK_DOMAIN'
  | 'BLOCK_IP'
  | 'BLOCK_URL'
  | 'QUARANTINE_EMAIL'
  | 'QUARANTINE_ATTACHMENT'
  | 'DISABLE_SENDER'
  | 'RESET_CREDENTIAL'
  | 'PRESERVE_EVIDENCE'
  | 'NOTIFY_SOC'
  | 'NOTIFY_USER'
  | 'ESCALATE'
  | 'INVESTIGATE'
  | 'MONITOR';

export type ActionStatus = 'PROPOSED' | 'APPROVED' | 'IN_PROGRESS' | 'COMPLETED' | 'REJECTED';

export type ArtifactType =
  | 'EMAIL'
  | 'EML_FILE'
  | 'IP'
  | 'DOMAIN'
  | 'URL'
  | 'ATTACHMENT'
  | 'HASH'
  | 'TIMELINE'
  | 'ATTACK_GRAPH'
  | 'THREAT_ASSESSMENT'
  | 'INTELLIGENCE_RESULT'
  | 'AI_ASSESSMENT'
  | 'BLOCKCHAIN_ANCHOR';

export interface CaseArtifact {
  artifact_id: string;
  artifact_type: ArtifactType;
  name: string;
  reference_id: string;
  description: string;
  sha256?: string;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface CaseNote {
  note_id: string;
  case_id: string;
  timestamp: string;
  author: string;
  content: string;
  category: NoteCategory;
}

export interface CaseAction {
  action_id: string;
  case_id: string;
  type: ActionType;
  title: string;
  description: string;
  priority: CasePriority;
  status: ActionStatus;
  created_at: string;
  completed_at?: string;
  actor: string;
  evidence_reference?: string;
  notes?: string;
}

export interface CaseTimelineEvent {
  event_id: string;
  case_id: string;
  timestamp: string;
  title: string;
  description: string;
  category: string;
  actor?: string;
  metadata?: Record<string, any>;
}

export interface CaseAuditEvent {
  event_id: string;
  case_id: string;
  timestamp: string;
  event_type: string;
  actor: string;
  details: string;
  previous_state?: string;
  new_state?: string;
  metadata?: Record<string, any>;
}

export interface IncidentCase {
  case_id: string;
  investigation_id?: string;
  title: string;
  description: string;
  status: CaseStatus;
  priority: CasePriority;
  verdict: IncidentVerdict;
  risk_score: number;
  confidence: number;
  assigned_analyst: string;
  lead_analyst?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
  closed_by?: string;
  closure_reason?: string;
  tags: string[];
  artifacts: CaseArtifact[];
  notes: CaseNote[];
  actions: CaseAction[];
  timeline_events: CaseTimelineEvent[];
  audit_events: CaseAuditEvent[];
  blockchain_verified: boolean;
  blockchain_tx_hash?: string;
  blockchain_block_number?: number;
  blockchain_record_hash?: string;
  threat_categories: string[];
  primary_indicator?: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  ai_summary?: string;
  root_cause?: string;
}

export interface CaseMetrics {
  total_cases: number;
  open_cases: number;
  closed_cases: number;
  by_priority: Record<string, number>;
  by_status: Record<string, number>;
  by_verdict: Record<string, number>;
  avg_resolution_hours: number;
  critical_containment_rate: number;
}

export interface CreateCaseRequest {
  title: string;
  description?: string;
  investigation_id?: string;
  priority?: CasePriority;
  assigned_analyst?: string;
  tags?: string[];
}

export interface UpdateCaseRequest {
  title?: string;
  description?: string;
  priority?: CasePriority;
  verdict?: IncidentVerdict;
  risk_score?: number;
  root_cause?: string;
}

export interface TransitionStatusRequest {
  new_status: CaseStatus;
  actor?: string;
  reason?: string;
}

export interface AssignCaseRequest {
  assigned_analyst: string;
  actor?: string;
}

export interface AddCaseNoteRequest {
  author?: string;
  content: string;
  category?: NoteCategory;
}

export interface AddCaseTagRequest {
  tag: string;
  actor?: string;
}

export interface CreateCaseActionRequest {
  type: ActionType;
  title: string;
  description: string;
  priority?: CasePriority;
  actor?: string;
  evidence_reference?: string;
}

export interface UpdateActionStatusRequest {
  status: ActionStatus;
  actor?: string;
  notes?: string;
}

export interface CloseCaseRequest {
  closed_by: string;
  closure_reason: string;
  verdict: IncidentVerdict;
  root_cause?: string;
}

export interface BlockchainVerificationResponse {
  case_id: string;
  verified: boolean;
  tamper_detected: boolean;
  blockchain_tx_hash?: string;
  blockchain_block_number?: number;
  blockchain_network?: string;
  message: string;
  timestamp: string;
}

export interface CaseAIRefreshResponse {
  case_id: string;
  ai_summary: string;
  recommended_actions: string[];
  threat_narrative: string;
  updated_at: string;
}
