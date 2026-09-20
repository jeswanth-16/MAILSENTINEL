import React, { useEffect, useState } from 'react';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { InvestigationSummary } from '../types/investigation';
import { fetchInvestigations } from '../services/investigationService';
import { History, FileText } from 'lucide-react';

export const CaseHistoryPage: React.FC = () => {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const data = await fetchInvestigations();
        setInvestigations(data.investigations);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <History className="w-5 h-5 text-soc-400" />
            <span>CASE_HISTORY_ARCHIVE</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Archived digital forensics records and resolved threat evaluations.
          </p>
        </div>
      </div>

      <Card noPadding>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-soc-800 text-[11px] font-mono text-soc-400 uppercase bg-soc-950/40">
                <th className="px-4 py-2.5">Case ID</th>
                <th className="px-4 py-2.5">Incident Title</th>
                <th className="px-4 py-2.5">Suspect Sender</th>
                <th className="px-4 py-2.5 text-center">Score</th>
                <th className="px-4 py-2.5">Status</th>
                <th className="px-4 py-2.5">Timestamp</th>
                <th className="px-4 py-2.5 text-right">Report</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-800/60 text-xs font-mono">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-soc-500">
                    Loading case archives...
                  </td>
                </tr>
              ) : (
                investigations.map((item) => (
                  <tr key={item.id} className="hover:bg-soc-850/50 transition-colors">
                    <td className="px-4 py-3 font-semibold text-blue-400">{item.id}</td>
                    <td className="px-4 py-3 font-sans font-medium text-soc-200">{item.title}</td>
                    <td className="px-4 py-3 text-soc-400">{item.sender}</td>
                    <td className="px-4 py-3 text-center">
                      <Badge variant="severity" severity={item.severity}>
                        {item.threat_score}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="status" status={item.status}>
                        {item.status}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-soc-500 text-[11px]">
                      {new Date(item.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button className="text-soc-400 hover:text-soc-100 p-1 rounded bg-soc-800 border border-soc-700">
                        <FileText className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
