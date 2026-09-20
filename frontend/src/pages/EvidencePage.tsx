import React, { useEffect, useState } from 'react';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { InvestigationSummary } from '../types/investigation';
import { fetchInvestigations } from '../services/investigationService';
import { FileCheck2, Hash, Copy, Check } from 'lucide-react';

export const EvidencePage: React.FC = () => {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const data = await fetchInvestigations();
        setInvestigations(data.investigations);
      } catch {
        // fallback
      }
    }
    load();
  }, []);

  const handleCopy = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-blue-400" />
            <span>EVIDENCE_MANAGEMENT_VAULT</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Cryptographic evidence custody vault with SHA-256 integrity verification.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        {investigations.map((item) => (
          <Card key={item.id} className="font-mono">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-soc-800/80 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-blue-400">{item.id}</span>
                <span className="text-xs font-sans text-soc-300 font-medium">{item.title}</span>
              </div>
              <Badge variant={item.blockchain_verified ? 'blockchain' : 'neutral'}>
                {item.blockchain_verified ? 'BLOCKCHAIN_ANCHORED' : 'PENDING_ANCHOR'}
              </Badge>
            </div>

            <div className="mt-3 space-y-2 text-xs">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between p-2.5 bg-soc-950 rounded border border-soc-800 gap-2">
                <div className="flex items-center gap-2 text-soc-400 truncate">
                  <Hash className="w-4 h-4 text-soc-500 flex-shrink-0" />
                  <span className="text-soc-500">SHA-256:</span>
                  <span className="text-soc-200 select-all truncate">{item.evidence_hash}</span>
                </div>
                <button
                  onClick={() => handleCopy(item.evidence_hash)}
                  className="px-2 py-1 bg-soc-800 hover:bg-soc-700 text-soc-300 rounded text-[11px] flex items-center gap-1 flex-shrink-0 transition-colors"
                >
                  {copiedHash === item.evidence_hash ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy Hash</span>
                    </>
                  )}
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] text-soc-500 pt-1">
                <div>Source: <span className="text-soc-300">Raw .EML RFC 5322 Ingestion</span></div>
                <div>Analyst: <span className="text-soc-300">{item.analyst}</span></div>
                <div>Recorded: <span className="text-soc-300">{new Date(item.created_at).toUTCString()}</span></div>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
};
