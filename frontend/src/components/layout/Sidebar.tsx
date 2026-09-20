import React from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  LayoutDashboard,
  FolderLock,
  History,
  MailSearch,
  Globe,
  Radar,
  GitCommit,
  Share2,
  FileCheck2,
  MapPin,
  Link2,
  FileText,
  Users,
  Settings as SettingsIcon,
} from 'lucide-react';
import { UserRole } from '../../types/auth';

interface NavItem {
  label: string;
  path: string;
  icon: React.ElementType;
  badge?: string;
  requiredRoles?: UserRole[];
  requiredPermission?: string;
}

interface NavSection {
  title?: string;
  requiredRoles?: UserRole[];
  items: NavItem[];
}

export const Sidebar: React.FC = () => {
  const { user, hasRole, hasPermission } = useAuth();

  const sections: NavSection[] = [
    {
      items: [
        { label: 'Overview', path: '/dashboard', icon: LayoutDashboard },
      ],
    },
    {
      title: 'INCIDENT RESPONSE',
      items: [
        { label: 'Case Management', path: '/cases', icon: ShieldAlert, badge: 'SOC' },
      ],
    },
    {
      title: 'INVESTIGATIONS',
      items: [
        { label: 'Active Cases', path: '/investigations/active', icon: FolderLock, badge: '3' },
        { label: 'Case History', path: '/investigations/history', icon: History },
      ],
    },
    {
      title: 'ANALYSIS',
      items: [
        { label: 'Email Analyzer', path: '/analysis/email', icon: MailSearch, requiredPermission: 'email:analyze' },
        { label: 'URL Intelligence', path: '/analysis/url', icon: Globe },
        { label: 'Threat Intelligence', path: '/analysis/threat', icon: Radar },
      ],
    },
    {
      title: 'FORENSICS',
      items: [
        { label: 'Timeline', path: '/forensics/timeline', icon: GitCommit },
        { label: 'Attack Graph', path: '/forensics/attack-graph', icon: Share2 },
        { label: 'Evidence', path: '/forensics/evidence', icon: FileCheck2 },
      ],
    },
    {
      title: 'INTELLIGENCE',
      items: [
        { label: 'Threat Map', path: '/intelligence/map', icon: MapPin },
      ],
    },
    {
      title: 'BLOCKCHAIN',
      items: [
        { label: 'Evidence Verification', path: '/blockchain/verification', icon: Link2 },
      ],
    },
    {
      title: 'REPORTS & EVIDENCE',
      items: [
        { label: 'Report Center', path: '/reports', icon: FileText, badge: 'PDF' },
        { label: 'Evidence Dossiers', path: '/reports/dossier', icon: FileCheck2 },
      ],
    },
    {
      title: 'ADMINISTRATION & RBAC',
      requiredRoles: ['ADMIN', 'AUDITOR'],
      items: [
        { label: 'User Directory', path: '/admin/users', icon: Users, requiredRoles: ['ADMIN'] },
        { label: 'Security & Audit', path: '/admin/security', icon: ShieldCheck, requiredRoles: ['ADMIN', 'AUDITOR'] },
      ],
    },
    {
      items: [
        { label: 'Settings', path: '/settings', icon: SettingsIcon },
      ],
    },
  ];

  const isItemVisible = (item: NavItem): boolean => {
    if (!user) return false;
    if (user.role === 'ADMIN') return true;
    if (item.requiredRoles && !hasRole(item.requiredRoles)) return false;
    if (item.requiredPermission && !hasPermission(item.requiredPermission)) return false;
    return true;
  };

  const isSectionVisible = (section: NavSection): boolean => {
    if (!user) return false;
    if (user.role === 'ADMIN') return true;
    if (section.requiredRoles && !hasRole(section.requiredRoles)) return false;
    return section.items.some(isItemVisible);
  };

  return (
    <aside className="w-64 flex-shrink-0 bg-soc-900 border-r border-soc-800 flex flex-col h-screen select-none">
      {/* Platform Branding */}
      <div className="h-16 flex items-center px-5 border-b border-soc-800 gap-3 bg-soc-950/40">
        <div className="w-9 h-9 rounded bg-blue-600/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className="font-bold tracking-wider text-white text-sm font-mono">MAILSENTINEL</span>
            <span className="text-[10px] px-1 py-0.2 rounded bg-soc-800 text-cyan-400 font-mono font-medium border border-soc-700">v1.4</span>
          </div>
          <p className="text-[10px] text-soc-400 font-medium tracking-tight">SOC & Forensic Intelligence</p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {sections.filter(isSectionVisible).map((section, idx) => {
          const visibleItems = section.items.filter(isItemVisible);
          if (visibleItems.length === 0) return null;

          return (
            <div key={idx} className="space-y-1">
              {section.title && (
                <h4 className="px-3 text-[10px] font-mono font-semibold tracking-wider text-soc-600 uppercase mb-2">
                  {section.title}
                </h4>
              )}
              {visibleItems.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      `flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-colors ${
                        isActive
                          ? 'bg-soc-800 text-cyan-400 border border-soc-700/80 shadow-inner'
                          : 'text-soc-400 hover:text-soc-200 hover:bg-soc-850/60'
                      }`
                    }
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className="w-4 h-4 opacity-80" />
                      <span>{item.label}</span>
                    </div>
                    {item.badge ? (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800/80">
                        {item.badge}
                      </span>
                    ) : null}
                  </NavLink>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* Security Context Footer */}
      <div className="p-3 border-t border-soc-800 bg-soc-950/30 text-[11px] font-mono text-soc-400">
        <div className="flex items-center justify-between">
          <span className="text-soc-600">ROLE_LEVEL</span>
          <span className="text-cyan-400 font-bold">{user?.role || 'ANONYMOUS'}</span>
        </div>
        <div className="flex items-center justify-between mt-1">
          <span className="text-soc-600">AUTH_STATUS</span>
          <span className="text-emerald-400">AUTHENTICATED</span>
        </div>
      </div>
    </aside>
  );
};
