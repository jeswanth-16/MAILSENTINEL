import React, { useState, useEffect } from 'react';
import { authService } from '../services/authService';
import { SecurityMetrics, SecurityAuditEvent } from '../types/auth';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Users,
  Lock,
  RefreshCw,
  Filter,
  CheckCircle2,
  XCircle,
} from 'lucide-react';

export const SecurityDashboardPage: React.FC = () => {
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [auditLogs, setAuditLogs] = useState<SecurityAuditEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState<string>('ALL');

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [m, logs] = await Promise.all([
        authService.getSecurityMetrics(),
        authService.getSecurityAuditLogs(50),
      ]);
      setMetrics(m);
      setAuditLogs(logs);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch security metrics.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const filteredLogs = auditLogs.filter((log) => {
    if (actionFilter === 'ALL') return true;
    return log.action.includes(actionFilter) || log.result === actionFilter;
  });

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">SOC Security & Access Control Dashboard</h1>
            <p className="text-xs text-slate-400">
              Live authentication telemetry, RBAC event audits, and security posture monitoring
            </p>
          </div>
        </div>

        <button
          onClick={fetchData}
          disabled={loading}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:text-white hover:bg-slate-700 transition text-xs font-semibold"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm">
          {error}
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Active / Total Users</span>
            <Users className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold text-white mt-2">
            {metrics ? `${metrics.active_users} / ${metrics.total_users}` : '—'}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">Provisioned SOC accounts</p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Failed Logins (24h)</span>
            <Lock className="w-4 h-4 text-amber-400" />
          </div>
          <p className="text-2xl font-bold text-amber-400 mt-2">
            {metrics ? metrics.failed_logins_24h : 0}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">Lockout threshold: 5 attempts</p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Access Denied (403)</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <p className="text-2xl font-bold text-rose-400 mt-2">
            {metrics ? metrics.access_denied_24h : 0}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">RBAC authorization blocks</p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Privileged Actions</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold text-emerald-400 mt-2">
            {metrics ? metrics.privileged_actions_24h : 0}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">Containment & administrative</p>
        </div>
      </div>

      {/* Security Posture Status */}
      <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          Production Security Hardening Posture
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/80">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold mb-1">
              <CheckCircle2 className="w-4 h-4" />
              <span>Password Hashing</span>
            </div>
            <p className="text-xs text-slate-300 font-mono">PBKDF2-HMAC-SHA256</p>
            <p className="text-[11px] text-slate-500 mt-0.5">200,000 iterations with constant-time verify</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/80">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold mb-1">
              <CheckCircle2 className="w-4 h-4" />
              <span>Session Protection</span>
            </div>
            <p className="text-xs text-slate-300 font-mono">Cryptographic JWT (HS256)</p>
            <p className="text-[11px] text-slate-500 mt-0.5">Signed access tokens + refresh token flow</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/80">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold mb-1">
              <CheckCircle2 className="w-4 h-4" />
              <span>Security Middleware</span>
            </div>
            <p className="text-xs text-slate-300 font-mono">Strict Headers & Rate Limiting</p>
            <p className="text-[11px] text-slate-500 mt-0.5">CSP, DENY frame-options, nosniff, CORS</p>
          </div>
        </div>
      </div>

      {/* Security Audit Trail */}
      <div className="bg-slate-900/60 rounded-2xl border border-slate-800 overflow-hidden backdrop-blur-xl">
        <div className="p-5 border-b border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Security Audit & Access Event Trail
            </h2>
            <p className="text-xs text-slate-400">
              Immutable record of analyst logins, role changes, containment actions, and access evaluations
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Events</option>
              <option value="LOGIN">Logins</option>
              <option value="CASE">Case Operations</option>
              <option value="RESPONSE">Response Actions</option>
              <option value="USER">User Admin</option>
              <option value="DENIED">Denied (403)</option>
              <option value="FAILURE">Failures</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/40 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Actor / Role</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Resource</th>
                <th className="py-3 px-4">Result</th>
                <th className="py-3 px-4">Source IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No security events recorded.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.event_id} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(log.timestamp).toLocaleTimeString([], { hour12: false })}
                    </td>

                    <td className="py-3 px-4">
                      <div>
                        <span className="font-semibold text-slate-200">{log.actor_user_id}</span>
                        <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          {log.actor_role}
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4 font-mono font-medium text-cyan-300">
                      {log.action}
                    </td>

                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      <span className="font-mono text-slate-300">{log.resource_type}:</span> {log.resource_id}
                    </td>

                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${
                          log.result === 'SUCCESS'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : log.result === 'DENIED'
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                        }`}
                      >
                        {log.result === 'SUCCESS' ? (
                          <CheckCircle2 className="w-2.5 h-2.5" />
                        ) : (
                          <XCircle className="w-2.5 h-2.5" />
                        )}
                        {log.result}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-slate-500 font-mono text-[11px]">
                      {log.source_ip}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
