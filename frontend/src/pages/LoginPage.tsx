import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, Mail, Key, Eye, EyeOff, AlertCircle, CheckCircle2, UserCheck } from 'lucide-react';
import { UserRole } from '../types/auth';

const DEMO_ACCOUNTS: Array<{
  role: UserRole;
  name: string;
  email: string;
  pass: string;
  badgeColor: string;
  description: string;
}> = [
  {
    role: 'ADMIN',
    name: 'SOC Administrator',
    email: 'admin@mailsentinel.local',
    pass: 'Admin@12345!',
    badgeColor: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    description: 'Full administrative access, user provisioning & tamper simulation',
  },
  {
    role: 'SENIOR_ANALYST',
    name: 'Lead Forensics Specialist',
    email: 'senior@mailsentinel.local',
    pass: 'Senior@12345!',
    badgeColor: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    description: 'Deep triage, AI correlation, action execution & case closure',
  },
  {
    role: 'SOC_ANALYST',
    name: 'SOC Tier-2 Analyst',
    email: 'analyst@mailsentinel.local',
    pass: 'Analyst@12345!',
    badgeColor: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    description: 'Email forensics, threat scoring, cases & action proposing',
  },
  {
    role: 'INCIDENT_RESPONDER',
    name: 'Incident Response Officer',
    email: 'responder@mailsentinel.local',
    pass: 'Responder@12345!',
    badgeColor: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    description: 'Active containment, endpoint isolation & response execution',
  },
  {
    role: 'AUDITOR',
    name: 'Forensic Evidence Auditor',
    email: 'auditor@mailsentinel.local',
    pass: 'Auditor@12345!',
    badgeColor: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    description: 'Read-only compliance audit, blockchain proof verification & logs',
  },
  {
    role: 'VIEWER',
    name: 'Executive SOC Viewer',
    email: 'viewer@mailsentinel.local',
    pass: 'Viewer@12345!',
    badgeColor: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
    description: 'Executive read-only dashboard for briefings & reports',
  },
];

export const LoginPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = (location.state as any)?.from?.pathname || '/';

  const handleLogin = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!email || !password) {
      setError('Please enter both email and password.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      await login(email, password);
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const selectDemoAccount = async (account: (typeof DEMO_ACCOUNTS)[0]) => {
    setEmail(account.email);
    setPassword(account.pass);
    setError(null);
    setLoading(true);

    try {
      await login(account.email, account.pass);
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || 'Quick login failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center px-4 py-12 relative overflow-hidden">
      {/* Ambient background glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-cyan-500/10 blur-[120px] pointer-events-none rounded-full" />
      <div className="absolute bottom-1/4 right-1/4 w-[400px] h-[300px] bg-indigo-500/10 blur-[100px] pointer-events-none rounded-full" />

      <div className="w-full max-w-4xl relative z-10 flex flex-col items-center">
        {/* Header Branding */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-400 text-xs font-mono mb-3">
            <Shield className="w-3.5 h-3.5" />
            <span>MAILSENTINEL SOC AUTHENTICATION v1.4</span>
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white flex items-center justify-center gap-2">
            SOC Command Center Access
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-md mx-auto">
            Zero-Trust Email Threat Intelligence, Forensic Integrity & Incident Response Portal
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 w-full">
          {/* Main Login Card */}
          <div className="lg:col-span-6 bg-slate-900/80 border border-slate-800 rounded-2xl p-6 sm:p-8 backdrop-blur-xl shadow-2xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-6">
                <div>
                  <h2 className="text-lg font-bold text-white">Analyst Sign In</h2>
                  <p className="text-xs text-slate-400">Authenticate with signed session credentials</p>
                </div>
                <div className="p-2 bg-slate-800 rounded-lg text-cyan-400">
                  <Lock className="w-5 h-5" />
                </div>
              </div>

              {error && (
                <div className="mb-6 p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-2.5">
                  <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    SOC Identity / Email
                  </label>
                  <div className="relative">
                    <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="analyst@mailsentinel.local"
                      required
                      className="w-full pl-10 pr-4 py-2.5 bg-slate-950/60 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    Password
                  </label>
                  <div className="relative">
                    <Key className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      required
                      className="w-full pl-10 pr-10 py-2.5 bg-slate-950/60 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-2 py-2.5 px-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold rounded-lg text-sm shadow-lg shadow-cyan-900/30 focus:outline-none transition disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      <span>Verifying Session...</span>
                    </>
                  ) : (
                    <>
                      <UserCheck className="w-4 h-4" />
                      <span>Authenticate Session</span>
                    </>
                  )}
                </button>
              </form>
            </div>

            <div className="mt-8 pt-4 border-t border-slate-800/80 text-[11px] text-slate-500 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                PBKDF2-HMAC-SHA256 (200k)
              </span>
              <span>Lockout: 5 Max Attempts</span>
            </div>
          </div>

          {/* Quick Login Role Switcher for SIH Jury & Demonstrations */}
          <div className="lg:col-span-6 flex flex-col justify-between space-y-4">
            <div className="bg-slate-900/50 border border-slate-800/80 rounded-2xl p-6 backdrop-blur-xl">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                    Demo Role Fast-Login
                  </h3>
                  <p className="text-xs text-slate-400">
                    Select a pre-configured role to experience role-based access control
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 text-[10px] font-mono border border-cyan-500/20">
                  1-CLICK DEMO
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {DEMO_ACCOUNTS.map((acc) => (
                  <button
                    key={acc.role}
                    type="button"
                    onClick={() => selectDemoAccount(acc)}
                    disabled={loading}
                    className="p-3 rounded-xl bg-slate-950/40 border border-slate-800/90 hover:border-slate-700 hover:bg-slate-800/40 text-left transition group relative overflow-hidden"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${acc.badgeColor}`}>
                        {acc.role}
                      </span>
                    </div>
                    <p className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition">
                      {acc.name}
                    </p>
                    <p className="text-[10px] text-slate-400 mt-1 line-clamp-2">
                      {acc.description}
                    </p>
                  </button>
                ))}
              </div>
            </div>

            {/* Security Assurance Banner */}
            <div className="bg-slate-900/40 border border-slate-800/60 rounded-xl p-4 text-xs text-slate-400 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Shield className="w-5 h-5 text-cyan-400 flex-shrink-0" />
                <div>
                  <p className="font-semibold text-slate-300">Strict SOC Access Control Enforced</p>
                  <p className="text-[11px] text-slate-500">
                    All session actions, case transitions, and evidence queries are audit-logged.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
