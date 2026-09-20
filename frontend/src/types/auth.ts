export type UserRole = 
  | 'ADMIN'
  | 'SENIOR_ANALYST'
  | 'SOC_ANALYST'
  | 'INCIDENT_RESPONDER'
  | 'AUDITOR'
  | 'VIEWER';

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  is_locked: boolean;
  created_at: string;
  last_login_at?: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface SecurityAuditEvent {
  event_id: string;
  timestamp: string;
  actor_user_id: string;
  actor_role: string;
  action: string;
  resource_type: string;
  resource_id: string;
  result: 'SUCCESS' | 'FAILURE' | 'DENIED' | string;
  source_ip: string;
  metadata: Record<string, any>;
}

export interface SecurityMetrics {
  total_users: number;
  active_users: number;
  locked_users: number;
  failed_logins_24h: number;
  access_denied_24h: number;
  privileged_actions_24h: number;
  rate_limit_events_24h: number;
}

export interface CreateUserRequest {
  email: string;
  password: string;
  full_name: string;
  role: UserRole;
}

export interface UpdateUserRoleRequest {
  role: UserRole;
}

export interface UpdateUserStatusRequest {
  is_active: boolean;
}

export interface ResetPasswordRequest {
  new_password: string;
}

export interface RolePermissionInfo {
  role: UserRole;
  name: string;
  description: string;
  color: string;
  permissions: string[];
}
