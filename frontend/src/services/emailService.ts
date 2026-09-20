import { EmailForensicResult } from '../types/emailForensics';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

export async function uploadAndAnalyzeEmail(file: File): Promise<EmailForensicResult> {
  const formData = new FormData();
  formData.append('file', file);

  const url = `${API_BASE_URL}/analysis/email`;

  const response = await fetch(url, {
    method: 'POST',
    body: formData,
    // Do not set Content-Type header manually; browser automatically sets boundary for multipart
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
      // Use fallback
    }
    throw new Error(errorMessage);
  }

  return (await response.json()) as EmailForensicResult;
}
