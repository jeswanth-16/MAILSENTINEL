import React from 'react';
import { ShieldAlert, ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';

export const NotFoundPage: React.FC = () => {
  return (
    <div className="h-96 flex flex-col items-center justify-center text-center space-y-4 font-mono">
      <ShieldAlert className="w-12 h-12 text-threat-critical" />
      <div>
        <h2 className="text-lg font-bold text-soc-100">404: RESOURCE_NOT_FOUND</h2>
        <p className="text-xs text-soc-500 mt-1">The requested investigation or module route does not exist.</p>
      </div>
      <Link
        to="/dashboard"
        className="inline-flex items-center gap-2 px-3 py-1.5 bg-soc-800 hover:bg-soc-700 text-soc-200 rounded text-xs transition-colors"
      >
        <ArrowLeft className="w-3.5 h-3.5" />
        <span>Return to SOC Overview</span>
      </Link>
    </div>
  );
};
