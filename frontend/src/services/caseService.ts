import { apiClient } from './api';
import {
  IncidentCase,
  CaseMetrics,
  CreateCaseRequest,
  UpdateCaseRequest,
  TransitionStatusRequest,
  AssignCaseRequest,
  AddCaseNoteRequest,
  AddCaseTagRequest,
  CreateCaseActionRequest,
  UpdateActionStatusRequest,
  CloseCaseRequest,
  CaseNote,
  CaseAction,
  CaseAuditEvent,
  BlockchainVerificationResponse,
  CaseAIRefreshResponse,
} from '../types/cases';

export interface CaseFilterParams {
  status?: string;
  priority?: string;
  verdict?: string;
  assigned_to?: string;
  search?: string;
  skip?: number;
  limit?: number;
}

export interface CaseListResponse {
  total: number;
  cases: IncidentCase[];
}

export async function fetchCases(params?: CaseFilterParams): Promise<CaseListResponse> {
  const query = new URLSearchParams();
  if (params?.status && params.status !== 'ALL') query.append('status', params.status);
  if (params?.priority && params.priority !== 'ALL') query.append('priority', params.priority);
  if (params?.verdict && params.verdict !== 'ALL') query.append('verdict', params.verdict);
  if (params?.assigned_to) query.append('assigned_to', params.assigned_to);
  if (params?.search) query.append('search', params.search);
  if (params?.skip !== undefined) query.append('skip', String(params.skip));
  if (params?.limit !== undefined) query.append('limit', String(params.limit));

  const qs = query.toString();
  return await apiClient<CaseListResponse>(`/cases${qs ? `?${qs}` : ''}`);
}

export async function fetchCaseMetrics(): Promise<CaseMetrics> {
  return await apiClient<CaseMetrics>('/cases/metrics');
}

export async function fetchCase(caseId: string): Promise<IncidentCase> {
  return await apiClient<IncidentCase>(`/cases/${caseId}`);
}

export async function createCase(payload: CreateCaseRequest): Promise<IncidentCase> {
  return await apiClient<IncidentCase>('/cases', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function updateCase(caseId: string, payload: UpdateCaseRequest): Promise<IncidentCase> {
  return await apiClient<IncidentCase>(`/cases/${caseId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

export async function transitionCaseStatus(
  caseId: string,
  payload: TransitionStatusRequest
): Promise<IncidentCase> {
  return await apiClient<IncidentCase>(`/cases/${caseId}/status`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function assignCaseAnalyst(
  caseId: string,
  payload: AssignCaseRequest
): Promise<IncidentCase> {
  return await apiClient<IncidentCase>(`/cases/${caseId}/assign`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function addCaseNote(
  caseId: string,
  payload: AddCaseNoteRequest
): Promise<CaseNote> {
  return await apiClient<CaseNote>(`/cases/${caseId}/notes`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function deleteCaseNote(
  caseId: string,
  noteId: string
): Promise<{ success: boolean; message: string }> {
  return await apiClient<{ success: boolean; message: string }>(
    `/cases/${caseId}/notes/${noteId}`,
    {
      method: 'DELETE',
    }
  );
}

export async function addCaseTag(
  caseId: string,
  payload: AddCaseTagRequest
): Promise<IncidentCase> {
  return await apiClient<IncidentCase>(`/cases/${caseId}/tags`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function removeCaseTag(
  caseId: string,
  tag: string
): Promise<IncidentCase> {
  return await apiClient<IncidentCase>(`/cases/${caseId}/tags/${encodeURIComponent(tag)}`, {
    method: 'DELETE',
  });
}

export async function createCaseAction(
  caseId: string,
  payload: CreateCaseActionRequest
): Promise<CaseAction> {
  return await apiClient<CaseAction>(`/cases/${caseId}/actions`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function updateCaseActionStatus(
  caseId: string,
  actionId: string,
  payload: UpdateActionStatusRequest
): Promise<CaseAction> {
  return await apiClient<CaseAction>(`/cases/${caseId}/actions/${actionId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

export async function closeIncidentCase(
  caseId: string,
  payload: CloseCaseRequest
): Promise<IncidentCase> {
  return await apiClient<IncidentCase>(`/cases/${caseId}/close`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function fetchCaseAuditLog(caseId: string): Promise<CaseAuditEvent[]> {
  return await apiClient<CaseAuditEvent[]>(`/cases/${caseId}/audit`);
}

export async function verifyCaseBlockchain(
  caseId: string
): Promise<BlockchainVerificationResponse> {
  return await apiClient<BlockchainVerificationResponse>(`/cases/${caseId}/blockchain/verify`, {
    method: 'POST',
  });
}

export async function refreshCaseAIAnalysis(
  caseId: string
): Promise<CaseAIRefreshResponse> {
  return await apiClient<CaseAIRefreshResponse>(`/cases/${caseId}/ai/refresh`, {
    method: 'POST',
  });
}
