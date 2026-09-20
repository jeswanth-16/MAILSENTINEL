import React from 'react';

interface StatusIndicatorProps {
  status: 'online' | 'offline' | 'loading' | 'warning';
  label?: string;
  size?: 'sm' | 'md';
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({
  status,
  label,
  size = 'sm',
}) => {
  const dotSize = size === 'sm' ? 'w-2 h-2' : 'w-2.5 h-2.5';
  
  let colorClass = 'bg-soc-600';
  let defaultLabel = 'Unknown';

  if (status === 'online') {
    colorClass = 'bg-emerald-500';
    defaultLabel = 'Online';
  } else if (status === 'offline') {
    colorClass = 'bg-red-500';
    defaultLabel = 'Offline';
  } else if (status === 'loading') {
    colorClass = 'bg-amber-400 animate-pulse';
    defaultLabel = 'Connecting...';
  } else if (status === 'warning') {
    colorClass = 'bg-amber-500';
    defaultLabel = 'Degraded';
  }

  return (
    <div className="inline-flex items-center gap-2 font-mono text-xs text-soc-300">
      <span className={`inline-block rounded-full ${dotSize} ${colorClass}`} />
      <span>{label || defaultLabel}</span>
    </div>
  );
};
