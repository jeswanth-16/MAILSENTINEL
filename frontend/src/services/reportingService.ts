import { apiClient } from './api';
import {
  ForensicReport,
  ReportManifest,
  GenerateReportRequest,
  VerifyReportResponse,
} from '../types/reporting';

const API_BASE = '/api/v1/reports';

export async function generateReport(
  caseId: string,
  payload: GenerateReportRequest = {}
): Promise<ForensicReport> {
  return await apiClient<ForensicReport>(`/reports/generate/${caseId}`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function fetchReport(caseId: string): Promise<ForensicReport> {
  return await apiClient<ForensicReport>(`/reports/${caseId}`);
}

export function getReportPdfUrl(caseId: string): string {
  return `${API_BASE}/${caseId}/pdf`;
}

export function getReportJsonUrl(caseId: string): string {
  return `${API_BASE}/${caseId}/json`;
}

export function getIocsCsvUrl(caseId: string): string {
  return `${API_BASE}/${caseId}/iocs.csv`;
}

export function getTimelineCsvUrl(caseId: string): string {
  return `${API_BASE}/${caseId}/timeline.csv`;
}

export function getFindingsCsvUrl(caseId: string): string {
  return `${API_BASE}/${caseId}/findings.csv`;
}

export function getPackageZipUrl(caseId: string): string {
  return `${API_BASE}/${caseId}/package`;
}

export async function fetchManifest(caseId: string): Promise<ReportManifest> {
  return await apiClient<ReportManifest>(`/reports/${caseId}/manifest`);
}

export async function verifyReportIntegrity(
  reportId: string,
  expectedHash?: string
): Promise<VerifyReportResponse> {
  return await apiClient<VerifyReportResponse>(`/reports/${reportId}/verify`, {
    method: 'POST',
    body: JSON.stringify({ expected_hash: expectedHash }),
  });
}
