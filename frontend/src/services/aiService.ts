import { apiClient } from './api';
import {
  AIAnalystAssessment,
  CorrelationResult,
  RelatedCase,
} from '../types/ai';

export async function fetchAIAssessment(investigationId: string): Promise<AIAnalystAssessment> {
  try {
    return await apiClient<AIAnalystAssessment>(`/investigations/${investigationId}/assessment`);
  } catch {
    return await apiClient<AIAnalystAssessment>(`/ai/assessment/${investigationId}`);
  }
}

export async function analyzeInvestigationWithAI(investigationId: string): Promise<AIAnalystAssessment> {
  return await apiClient<AIAnalystAssessment>(`/ai/analyze/${investigationId}`, {
    method: 'POST',
  });
}

export async function fetchCorrelation(investigationId: string): Promise<CorrelationResult> {
  return await apiClient<CorrelationResult>(`/ai/correlation/${investigationId}`);
}

export async function fetchRelatedCases(investigationId: string): Promise<RelatedCase[]> {
  return await apiClient<RelatedCase[]>(`/ai/related-cases/${investigationId}`);
}

export async function refreshAIAssessment(investigationId: string): Promise<AIAnalystAssessment> {
  try {
    return await apiClient<AIAnalystAssessment>(`/investigations/${investigationId}/assessment/recalculate`, {
      method: 'POST',
    });
  } catch {
    return await apiClient<AIAnalystAssessment>(`/ai/refresh/${investigationId}`, {
      method: 'POST',
    });
  }
}

export const recalculateAssessment = refreshAIAssessment;

