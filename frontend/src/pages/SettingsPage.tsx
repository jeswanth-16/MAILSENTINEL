import React from 'react';
import { Card } from '../components/common/Card';
import { Settings as SettingsIcon } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <SettingsIcon className="w-5 h-5 text-soc-400" />
            <span>PLATFORM_SETTINGS_&_SYSTEM_STATUS</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Engine threshold configuration, API keys, database connection, and EVM network nodes.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
        <Card title="System Environment & Nodes">
          <div className="space-y-3">
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">API Gateway:</span>
              <span className="text-soc-200">FastAPI 0.110+ (Port 8000)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Storage Architecture:</span>
              <span className="text-soc-200">PostgreSQL (Dev In-Memory Fallback)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">EVM Ledger Node:</span>
              <span className="text-cyan-400">Local Hardhat / Sepolia Testnet</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Log Verbosity:</span>
              <span className="text-soc-200">INFO (Structured JSON Stream)</span>
            </div>
          </div>
        </Card>

        <Card title="Threat Scoring Weights">
          <div className="space-y-3">
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Authentication Failure (SPF/DMARC):</span>
              <span className="text-threat-critical font-bold">+35 pts</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Lookalike Domain Homoglyph:</span>
              <span className="text-threat-high font-bold">+25 pts</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Urgency & Credential Harvesting Intent:</span>
              <span className="text-threat-medium font-bold">+20 pts</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Suspicious Infrastructure / ASN:</span>
              <span className="text-threat-medium font-bold">+20 pts</span>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};
