import { Search, PlusCircle, UserCheck, RefreshCw, LogOut } from 'lucide-react';
import { StatusIndicator } from '../common/StatusIndicator';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { UserRole } from '../../types/auth';

interface HeaderProps {
  backendStatus: 'online' | 'offline' | 'loading';
  backendVersion?: string;
  onRefreshStatus?: () => void;
  onOpenNewInvestigation?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  backendStatus,
  backendVersion,
  onRefreshStatus,
  onOpenNewInvestigation,
}) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const getRoleBadgeStyle = (role?: UserRole) => {
    switch (role) {
      case 'ADMIN':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'SENIOR_ANALYST':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      case 'SOC_ANALYST':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
      case 'INCIDENT_RESPONDER':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'AUDITOR':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'VIEWER':
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <header className="h-16 bg-soc-900 border-b border-soc-800 px-6 flex items-center justify-between flex-shrink-0">
      {/* Quick Search */}
      <div className="flex items-center gap-4 w-96">
        <div className="relative w-full">
          <Search className="w-4 h-4 text-soc-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            placeholder="Search IOC, Domain, SHA-256, Case ID..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-soc-950 border border-soc-800 rounded text-soc-200 placeholder-soc-600 focus:outline-none focus:border-blue-500/70 font-mono transition-colors"
          />
        </div>
      </div>

      {/* Center/Right Status & Profile Controls */}
      <div className="flex items-center gap-4">
        {/* Backend API Live Status */}
        <div 
          onClick={onRefreshStatus}
          title="Click to re-verify API Gateway health"
          className="flex items-center gap-2 px-2.5 py-1 rounded bg-soc-950/60 border border-soc-800 cursor-pointer hover:border-soc-700 transition-colors"
        >
          <span className="text-[11px] font-mono text-soc-600 uppercase">API:</span>
          <StatusIndicator
            status={backendStatus}
            label={backendStatus === 'online' ? `API Online (${backendVersion || 'v1.4'})` : backendStatus === 'loading' ? 'Checking API...' : 'API Offline'}
          />
          {onRefreshStatus && (
            <RefreshCw className="w-3 h-3 text-soc-600 hover:text-soc-300 ml-1" />
          )}
        </div>

        {/* Quick Action Button */}
        {onOpenNewInvestigation ? (
          <button
            onClick={onOpenNewInvestigation}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-colors"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            <span>+ New Investigation</span>
          </button>
        ) : (
          <Link
            to="/investigations/active"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-colors"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            <span>+ New Investigation</span>
          </Link>
        )}

        {/* Separator */}
        <div className="w-px h-6 bg-soc-800"></div>

        {/* Analyst Identity & Role Badge */}
        {user ? (
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-soc-800 border border-soc-700 flex items-center justify-center text-soc-300">
                <UserCheck className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-left hidden sm:block">
                <div className="text-xs font-semibold text-soc-100 flex items-center gap-1.5">
                  <span>{user.full_name}</span>
                  <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border ${getRoleBadgeStyle(user.role)}`}>
                    {user.role}
                  </span>
                </div>
                <div className="text-[10px] text-soc-500 font-mono truncate max-w-[150px]">{user.email}</div>
              </div>
            </div>

            {/* Logout Button */}
            <button
              onClick={handleLogout}
              title="Sign Out of SOC Session"
              className="p-1.5 rounded-lg bg-soc-800/80 border border-soc-700 text-soc-400 hover:text-rose-400 hover:bg-rose-950/30 hover:border-rose-800/40 transition"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <Link
            to="/login"
            className="px-3 py-1.5 rounded bg-cyan-600 text-white text-xs font-semibold hover:bg-cyan-500 transition"
          >
            Sign In
          </Link>
        )}
      </div>
    </header>
  );
};
