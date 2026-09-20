import { apiClient } from './api';
import {
  Investigation,
  InvestigationListResponse,
  InvestigationOverview,
  DashboardStats,
  AnalystNote,
  RunFullInvestigationResult,
  InvestigationReportData,
} from '../types/investigation';

export interface InvestigationFilterParams {
  status?: string;
  severity?: string;
  classification?: string;
  search?: string;
  sort_by?: string;
  descending?: boolean;
}

export async function fetchInvestigations(
  params?: InvestigationFilterParams
): Promise<InvestigationListResponse> {
  const query = new URLSearchParams();
  if (params?.status && params.status !== 'ALL') query.append('status', params.status);
  if (params?.severity && params.severity !== 'ALL') query.append('severity', params.severity);
  if (params?.classification && params.classification !== 'ALL') query.append('classification', params.classification);
  if (params?.search) query.append('search', params.search);
  if (params?.sort_by) query.append('sort_by', params.sort_by);
  if (params?.descending !== undefined) query.append('descending', String(params.descending));

  const qs = query.toString();
  return await apiClient<InvestigationListResponse>(`/investigations${qs ? `?${qs}` : ''}`);
}

export async function fetchInvestigation(investigationId: string): Promise<Investigation> {
  return await apiClient<Investigation>(`/investigations/${investigationId}`);
}

export async function fetchInvestigationOverview(
  investigationId: string
): Promise<InvestigationOverview> {
  return await apiClient<InvestigationOverview>(`/investigations/${investigationId}/overview`);
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  return await apiClient<DashboardStats>('/investigations/stats/dashboard');
}

export async function createInvestigation(payload: Partial<Investigation>): Promise<Investigation> {
  return await apiClient<Investigation>('/investigations', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function updateInvestigation(
  investigationId: string,
  payload: Partial<Investigation>
): Promise<Investigation> {
  return await apiClient<Investigation>(`/investigations/${investigationId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

export async function deleteInvestigation(investigationId: string): Promise<void> {
  await apiClient<void>(`/investigations/${investigationId}`, {
    method: 'DELETE',
  });
}

export async function addInvestigationNote(
  investigationId: string,
  content: string,
  author = 'SOC Analyst',
  noteType = 'NOTE'
): Promise<AnalystNote> {
  return await apiClient<AnalystNote>(`/investigations/${investigationId}/notes`, {
    method: 'POST',
    body: JSON.stringify({
      author,
      content,
      note_type: noteType,
    }),
  });
}

export async function deleteInvestigationNote(
  investigationId: string,
  noteId: string
): Promise<void> {
  await apiClient<void>(`/investigations/${investigationId}/notes/${noteId}`, {
    method: 'DELETE',
  });
}

export async function assignAnalyst(
  investigationId: string,
  analyst: string
): Promise<Investigation> {
  return await apiClient<Investigation>(`/investigations/${investigationId}/assign`, {
    method: 'POST',
    body: JSON.stringify({ analyst }),
  });
}

export async function updateInvestigationStatus(
  investigationId: string,
  status: string,
  reason = '',
  analyst = 'SOC Analyst'
): Promise<Investigation> {
  return await apiClient<Investigation>(`/investigations/${investigationId}/status`, {
    method: 'POST',
    body: JSON.stringify({ status, reason, analyst }),
  });
}

export async function updateInvestigationTags(
  investigationId: string,
  tags: string[]
): Promise<Investigation> {
  return await apiClient<Investigation>(`/investigations/${investigationId}/tags`, {
    method: 'POST',
    body: JSON.stringify({ tags }),
  });
}

export async function escalateInvestigation(
  investigationId: string,
  reason: string,
  escalateTo = 'TIER_3_INCIDENT_RESPONSE',
  analyst = 'SOC Analyst'
): Promise<Investigation> {
  return await apiClient<Investigation>(`/investigations/${investigationId}/escalate`, {
    method: 'POST',
    body: JSON.stringify({ reason, escalate_to: escalateTo, analyst }),
  });
}

export async function markFalsePositive(
  investigationId: string,
  reason: string,
  analyst = 'SOC Analyst'
): Promise<Investigation> {
  return await apiClient<Investigation>(`/investigations/${investigationId}/false-positive`, {
    method: 'POST',
    body: JSON.stringify({ reason, analyst }),
  });
}

export async function runFullInvestigation(
  file: File,
  analyst = 'SOC-L2-ANALYST'
): Promise<RunFullInvestigationResult> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('analyst', analyst);

  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';
  const response = await fetch(`${API_BASE_URL}/investigations/run-full`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${response.status}: ${response.statusText}`);
  }

  return await response.json();
}

export async function fetchInvestigationReport(
  investigationId: string
): Promise<InvestigationReportData> {
  return await apiClient<InvestigationReportData>(`/investigations/${investigationId}/report`);
}
