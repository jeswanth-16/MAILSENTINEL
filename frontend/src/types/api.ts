export interface HealthResponse {
  status: string;
  service: string;
  version?: string;
}

export interface ApiResponse<T> {
  data?: T;
  error?: string;
  timestamp: string;
}
