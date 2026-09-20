import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { User, UserRole } from '../types/auth';
import { authService } from '../services/authService';
import { TOKEN_STORAGE_KEY, USER_STORAGE_KEY } from '../services/api';

// Frontend RBAC permission map aligned with backend
const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  ADMIN: [
    'dashboard:view', 'email:analyze', 'investigation:view', 'investigation:create',
    'intelligence:view', 'ai:request', 'case:view', 'case:create', 'case:update',
    'action:propose', 'action:approve', 'action:execute', 'case:close',
    'report:view', 'report:generate', 'evidence:export', 'blockchain:verify',
    'blockchain:anchor', 'blockchain:simulate_tamper', 'audit:view', 'users:manage', 'security:config'
  ],
  SENIOR_ANALYST: [
    'dashboard:view', 'email:analyze', 'investigation:view', 'investigation:create',
    'intelligence:view', 'ai:request', 'case:view', 'case:create', 'case:update',
    'action:propose', 'action:approve', 'action:execute', 'case:close',
    'report:view', 'report:generate', 'evidence:export', 'blockchain:verify',
    'blockchain:anchor', 'audit:view'
  ],
  SOC_ANALYST: [
    'dashboard:view', 'email:analyze', 'investigation:view', 'investigation:create',
    'intelligence:view', 'ai:request', 'case:view', 'case:create', 'case:update',
    'action:propose', 'report:view', 'report:generate', 'evidence:export',
    'blockchain:verify', 'blockchain:anchor'
  ],
  INCIDENT_RESPONDER: [
    'dashboard:view', 'investigation:view', 'case:view', 'case:update',
    'action:propose', 'action:approve', 'action:execute', 'report:view',
    'evidence:export', 'blockchain:verify'
  ],
  AUDITOR: [
    'dashboard:view', 'investigation:view', 'case:view', 'report:view',
    'evidence:export', 'blockchain:verify', 'audit:view'
  ],
  VIEWER: [
    'dashboard:view', 'investigation:view', 'case:view', 'report:view',
    'blockchain:verify'
  ]
};

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  hasRole: (roles: UserRole | UserRole[]) => boolean;
  hasPermission: (permission: string) => boolean;
  refreshProfile: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    const saved = localStorage.getItem(USER_STORAGE_KEY);
    if (saved) {
      try {
        return JSON.parse(saved) as User;
      } catch {
        return null;
      }
    }
    return null;
  });

  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem(TOKEN_STORAGE_KEY);
  });

  const [isLoading, setIsLoading] = useState<boolean>(true);

  const refreshProfile = useCallback(async () => {
    const storedToken = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!storedToken) {
      setUser(null);
      setToken(null);
      setIsLoading(false);
      return;
    }

    try {
      const profile = await authService.getMe();
      setUser(profile);
      setToken(storedToken);
    } catch {
      // If token expired or invalid, reset
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      localStorage.removeItem(USER_STORAGE_KEY);
      setUser(null);
      setToken(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshProfile();
  }, [refreshProfile]);

  const login = async (email: string, password: string) => {
    setIsLoading(true);
    try {
      const resp = await authService.login(email, password);
      setToken(resp.access_token);
      setUser(resp.user);
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setIsLoading(true);
    try {
      await authService.logout();
    } finally {
      setToken(null);
      setUser(null);
      setIsLoading(false);
    }
  };

  const hasRole = useCallback((roles: UserRole | UserRole[]): boolean => {
    if (!user) return false;
    if (user.role === 'ADMIN') return true; // Admin has universal role authority
    const roleList = Array.isArray(roles) ? roles : [roles];
    return roleList.includes(user.role);
  }, [user]);

  const hasPermission = useCallback((permission: string): boolean => {
    if (!user) return false;
    const permissions = ROLE_PERMISSIONS[user.role] || [];
    return permissions.includes(permission);
  }, [user]);

  const value: AuthContextType = {
    user,
    token,
    isAuthenticated: !!token && !!user,
    isLoading,
    login,
    logout,
    hasRole,
    hasPermission,
    refreshProfile,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
