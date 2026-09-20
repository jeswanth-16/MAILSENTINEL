import { apiClient } from './api';
import { HealthResponse } from '../types/api';

export async function fetchHealthStatus(): Promise<HealthResponse> {
  return await apiClient<HealthResponse>('/health');
}
