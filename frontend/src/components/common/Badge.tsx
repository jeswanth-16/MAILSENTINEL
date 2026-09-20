import React from 'react';
import { ThreatSeverity, CaseStatus } from '../../types/investigation';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'severity' | 'status' | 'default' | 'neutral' | 'blockchain';
  severity?: ThreatSeverity | string;
  status?: CaseStatus | string;
  size?: 'sm' | 'md';
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  severity,
  status,
  size = 'sm',
  className = '',
}) => {
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-semibold';
  
  let colorClasses = 'bg-soc-800 text-soc-300 border-soc-700';

  if (variant === 'severity' && severity) {
    switch (severity) {
      case 'CRITICAL':
        colorClasses = 'bg-red-950/80 text-red-400 border-red-800/80 font-mono font-medium';
        break;
      case 'HIGH':
        colorClasses = 'bg-orange-950/80 text-orange-400 border-orange-800/80 font-mono font-medium';
        break;
      case 'MEDIUM':
        colorClasses = 'bg-amber-950/80 text-amber-400 border-amber-800/80 font-mono font-medium';
        break;
      case 'LOW':
        colorClasses = 'bg-blue-950/80 text-blue-400 border-blue-800/80 font-mono font-medium';
        break;
      case 'CLEAN':
        colorClasses = 'bg-emerald-950/80 text-emerald-400 border-emerald-800/80 font-mono font-medium';
        break;
    }
  } else if (variant === 'status' && status) {
    switch (status) {
      case 'NEW':
      case 'OPEN':
        colorClasses = 'bg-blue-950/60 text-blue-300 border-blue-800';
        break;
      case 'TRIAGING':
      case 'IN_REVIEW':
        colorClasses = 'bg-purple-950/60 text-purple-300 border-purple-800';
        break;
      case 'INVESTIGATING':
        colorClasses = 'bg-amber-950/60 text-amber-300 border-amber-800';
        break;
      case 'CONTAINED':
        colorClasses = 'bg-cyan-950/60 text-cyan-300 border-cyan-800';
        break;
      case 'RESOLVED':
        colorClasses = 'bg-emerald-950/60 text-emerald-300 border-emerald-800';
        break;
      case 'FALSE_POSITIVE':
        colorClasses = 'bg-zinc-900 text-zinc-400 border-zinc-700';
        break;
      case 'CLOSED':
      default:
        colorClasses = 'bg-soc-800 text-soc-400 border-soc-700';
        break;
    }
  } else if (variant === 'blockchain') {
    colorClasses = 'bg-cyan-950/60 text-cyan-300 border-cyan-800/70 font-mono';
  }

  return (
    <span
      className={`inline-flex items-center gap-1 border rounded font-sans tracking-wide uppercase ${sizeClasses} ${colorClasses} ${className}`}
    >
      {children}
    </span>
  );
};
