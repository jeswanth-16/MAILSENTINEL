import { apiClient, TOKEN_STORAGE_KEY, USER_STORAGE_KEY } from './api';
import {
  User,
  TokenResponse,
  SecurityMetrics,
  SecurityAuditEvent,
  CreateUserRequest,
  UpdateUserRoleRequest,
  UpdateUserStatusRequest,
  ResetPasswordRequest,
  UserRole,
} from '../types/auth';

export const authService = {
  async login(email: string, password: string): Promise<TokenResponse> {
    const data = await apiClient<TokenResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    if (data.access_token) {
      localStorage.setItem(TOKEN_STORAGE_KEY, data.access_token);
      localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(data.user));
    }

    return data;
  },

  async logout(): Promise<void> {
    try {
      await apiClient<{ message: string }>('/auth/logout', { method: 'POST' });
    } catch {
      // Ignore network errors during logout
    } finally {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      localStorage.removeItem(USER_STORAGE_KEY);
    }
  },

  async getMe(): Promise<User> {
    const user = await apiClient<User>('/auth/me');
    localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
    return user;
  },

  // Admin User Management
  async getUsers(): Promise<User[]> {
    return apiClient<User[]>('/admin/users');
  },

  async createUser(data: CreateUserRequest): Promise<User> {
    return apiClient<User>('/admin/users', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updateUserRole(userId: string, role: UserRole): Promise<User> {
    const payload: UpdateUserRoleRequest = { role };
    return apiClient<User>(`/admin/users/${userId}/role`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  async updateUserStatus(userId: string, isActive: boolean): Promise<User> {
    const payload: UpdateUserStatusRequest = { is_active: isActive };
    return apiClient<User>(`/admin/users/${userId}/status`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  async resetPassword(userId: string, newPassword: string): Promise<{ message: string }> {
    const payload: ResetPasswordRequest = { new_password: newPassword };
    return apiClient<{ message: string }>(`/admin/users/${userId}/reset-password`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Security Metrics & Audit Logs
  async getSecurityMetrics(): Promise<SecurityMetrics> {
    return apiClient<SecurityMetrics>('/admin/security/metrics');
  },

  async getSecurityAuditLogs(limit: number = 50, action?: string, actorUserId?: string): Promise<SecurityAuditEvent[]> {
    const params = new URLSearchParams();
    params.set('limit', limit.toString());
    if (action) params.set('action', action);
    if (actorUserId) params.set('actor_user_id', actorUserId);
    return apiClient<SecurityAuditEvent[]>(`/admin/security/audit-logs?${params.toString()}`);
  },
};
