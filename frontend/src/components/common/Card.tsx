import React from 'react';

interface CardProps {
  title?: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  noPadding?: boolean;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  action,
  children,
  className = '',
  noPadding = false,
}) => {
  return (
    <div className={`bg-soc-900 border border-soc-800 rounded-md shadow-sm ${className}`}>
      {(title || subtitle || action) && (
        <div className="px-4 py-3 border-b border-soc-800 flex items-center justify-between">
          <div>
            {title && <h3 className="text-sm font-semibold text-soc-100 uppercase tracking-wider">{title}</h3>}
            {subtitle && <p className="text-xs text-soc-400 mt-0.5">{subtitle}</p>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      <div className={noPadding ? '' : 'p-4'}>{children}</div>
    </div>
  );
};
