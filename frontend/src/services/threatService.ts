import { EmailForensicResult } from '../types/emailForensics';
import { ThreatAssessmentResult } from '../types/threatAssessment';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

export async function assessThreat(forensic: EmailForensicResult): Promise<ThreatAssessmentResult> {
  const url = `${API_BASE_URL}/analysis/threat`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(forensic),
  });

  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errorData = await response.json();
      if (errorData.detail) {
        errorMessage = typeof errorData.detail === 'string' ? errorData.detail : JSON.stringify(errorData.detail);
      } else if (errorData.message) {
        errorMessage = errorData.message;
      }
    } catch {
      // Use default fallback
    }
    throw new Error(errorMessage);
  }

  return (await response.json()) as ThreatAssessmentResult;
}
