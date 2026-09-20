import { AttackGraphResponse, TimelineResponse } from '../types/forensics';
import { EmailForensicResult } from '../types/emailForensics';
import { ThreatAssessmentResult } from '../types/threatAssessment';
import { InvestigationIntelligenceResult } from '../types/intelligence';


const API_BASE = '/api/v1';

export async function getInvestigationTimeline(
  investigationId: string,
  sort: string = 'asc',
  severity?: string,
  eventType?: string
): Promise<TimelineResponse> {
  const params = new URLSearchParams({ sort });
  if (severity && severity !== 'ALL') params.append('severity', severity);
  if (eventType && eventType !== 'ALL') params.append('event_type', eventType);

  const response = await fetch(
    `${API_BASE}/investigations/${encodeURIComponent(investigationId)}/timeline?${params.toString()}`
  );

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch timeline (Status: ${response.status})`);
  }

  return response.json();
}

export async function getInvestigationGraph(investigationId: string): Promise<AttackGraphResponse> {
  const response = await fetch(
    `${API_BASE}/investigations/${encodeURIComponent(investigationId)}/graph`
  );

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch attack graph (Status: ${response.status})`);
  }

  return response.json();
}

export async function generateTimeline(
  forensic: EmailForensicResult,
  threatAssessment?: ThreatAssessmentResult,
  intelligence?: InvestigationIntelligenceResult
): Promise<TimelineResponse> {
  const response = await fetch(`${API_BASE}/forensics/timeline`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      forensic,
      threat_assessment: threatAssessment,
      intelligence,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to generate timeline (Status: ${response.status})`);
  }

  return response.json();
}

export async function generateGraph(
  forensic: EmailForensicResult,
  threatAssessment?: ThreatAssessmentResult,
  intelligence?: InvestigationIntelligenceResult
): Promise<AttackGraphResponse> {
  const response = await fetch(`${API_BASE}/forensics/graph`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      forensic,
      threat_assessment: threatAssessment,
      intelligence,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to generate graph (Status: ${response.status})`);
  }

  return response.json();
}
