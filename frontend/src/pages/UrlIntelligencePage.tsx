import React, { useState } from 'react';
import { Card } from '../components/common/Card';
import { Globe } from 'lucide-react';

export const UrlIntelligencePage: React.FC = () => {
  const [urlInput, setUrlInput] = useState<string>('https://login-microsoft365-verify.com/auth');

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <Globe className="w-5 h-5 text-blue-400" />
            <span>URL_&_DOMAIN_INTELLIGENCE</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Domain age, DNS MX/A records, lookalike typo-squatting detection, and URL sandbox intelligence.
          </p>
        </div>
      </div>

      <Card title="Direct URL / Domain IOC Lookup">
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="Enter URL or Domain name (e.g. https://suspicious-domain.com)..."
            className="flex-1 px-3 py-2 text-xs bg-soc-950 border border-soc-800 rounded font-mono text-soc-200 placeholder-soc-600 focus:outline-none focus:border-blue-500"
          />
          <button className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded font-mono text-xs font-semibold">
            Query IOC
          </button>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Domain Reputation & Typo-Squatting Analysis">
          <div className="space-y-3 text-xs font-mono">
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Target Domain:</span>
              <span className="text-soc-200">login-microsoft365-verify.com</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Domain Age:</span>
              <span className="text-threat-critical font-semibold">3 Days Old (Freshly Registered)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Lookalike Target:</span>
              <span className="text-threat-high">microsoft.com (Typosquatting score 98%)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Registrar:</span>
              <span className="text-soc-200">NameCheap, Inc. (Privacy Protected)</span>
            </div>
          </div>
        </Card>

        <Card title="DNS & Infrastructure Intelligence">
          <div className="space-y-3 text-xs font-mono">
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Resolving IP (A Record):</span>
              <span className="text-soc-200">185.220.101.5</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">ASN / ISP:</span>
              <span className="text-soc-200">AS208323 (Offshore Bulletproof Host)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">Geo Location:</span>
              <span className="text-soc-200">Amsterdam, Netherlands (NL)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-soc-800">
              <span className="text-soc-500">MX Mail Server:</span>
              <span className="text-threat-medium">No MX configured (Outbound spoof only)</span>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};
