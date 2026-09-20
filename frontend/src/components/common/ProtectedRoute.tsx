import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { UserRole } from '../../types/auth';
import { ShieldAlert } from 'lucide-react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  allowedRoles?: UserRole[];
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, allowedRoles }) => {
  const { user, isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-slate-950 text-slate-100">
        <div className="flex flex-col items-center space-y-4">
          <div className="h-10 w-10 animate-spin rounded-full border-4 border-cyan-500 border-t-transparent"></div>
          <p className="text-sm font-medium tracking-wide text-slate-400">Verifying SOC Security Credentials...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles && allowedRoles.length > 0) {
    const isAuthorized = user.role === 'ADMIN' || allowedRoles.includes(user.role);
    if (!isAuthorized) {
      return (
        <div className="flex h-[calc(100vh-8rem)] w-full items-center justify-center p-6">
          <div className="max-w-md rounded-xl border border-rose-500/30 bg-rose-950/20 p-8 text-center backdrop-blur-md">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-rose-500/10 text-rose-400">
              <ShieldAlert className="h-8 w-8" />
            </div>
            <h2 className="text-xl font-bold text-slate-100">403 — Access Denied</h2>
            <p className="mt-2 text-sm text-slate-400">
              Your active role <span className="font-semibold text-rose-400">({user.role})</span> does not have sufficient RBAC permissions to access this SOC resource.
            </p>
            <div className="mt-6 flex justify-center space-x-3">
              <a
                href="/"
                className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition"
              >
                Return to SOC Dashboard
              </a>
            </div>
          </div>
        </div>
      );
    }
  }

  return <>{children}</>;
};
