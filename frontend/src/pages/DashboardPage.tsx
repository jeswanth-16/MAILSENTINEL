import React, { useEffect, useState } from 'react';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { InvestigationSummary, DashboardStats, ThreatSeverity } from '../types/investigation';
import {
  fetchInvestigations,
  fetchDashboardStats,
} from '../services/investigationService';
import {
  ShieldAlert,
  Activity,
  Layers,
  Link2,
  ExternalLink,
  ArrowUpRight,
  Clock,
  AlertTriangle,
  Server,
  FileCheck,
  Hash,
  Zap,
  Cpu,
} from 'lucide-react';
import { NewInvestigationModal } from '../components/investigation/NewInvestigationModal';
import { Link, useNavigate } from 'react-router-dom';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isNewModalOpen, setIsNewModalOpen] = useState<boolean>(false);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [casesData, statsData] = await Promise.all([
          fetchInvestigations(),
          fetchDashboardStats(),
        ]);
        setInvestigations(casesData.investigations);
        setStats(statsData);
        setError(null);
      } catch (err: any) {
        setError(err.message || 'Failed to communicate with backend API');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const totalCases = stats ? stats.total_investigations : investigations.length;
  const criticalCount = stats ? stats.critical_cases : investigations.filter((i) => i.severity === 'CRITICAL').length;
  const highCount = stats ? stats.high_cases : investigations.filter((i) => i.severity === 'HIGH').length;
  const blockchainVerifiedCount = stats ? stats.blockchain_verified_count : investigations.filter((i) => i.blockchain_verified).length;
  const verifiedPercentage = stats ? stats.blockchain_verified_percentage : (totalCases > 0 ? Math.round((blockchainVerifiedCount / totalCases) * 100) : 100);

  return (
    <div className="space-y-6">
      {/* Page Title & Status Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <span>SOC_COMMAND_OVERVIEW // UNIFIED_OPERATIONS</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Real-time email forensic triage, risk scoring pipeline & immutable evidence verification status.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsNewModalOpen(true)}
            className="px-3.5 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-mono text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Zap className="w-3.5 h-3.5 text-yellow-300" />
            <span>+ New Investigation</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <Card className="bg-soc-900/90 border-soc-800">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-medium text-soc-400 uppercase">Active Inquiries</span>
            <Layers className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-soc-100">
              {loading ? '...' : totalCases}
            </span>
            <span className="text-[11px] text-soc-500 font-mono">CASES</span>
          </div>
          <div className="mt-2 text-[11px] text-soc-400 flex items-center gap-1 font-mono">
            <span className="text-blue-400">● 100%</span> automated forensic triage
          </div>
        </Card>

        {/* Metric 2 */}
        <Card className="bg-soc-900/90 border-soc-800">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-medium text-soc-400 uppercase">Critical / High Threats</span>
            <ShieldAlert className="w-4 h-4 text-threat-critical" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-threat-critical">
              {loading ? '...' : criticalCount + highCount}
            </span>
            <span className="text-[11px] text-soc-500 font-mono">DETECTED</span>
          </div>
          <div className="mt-2 text-[11px] text-soc-400 flex items-center gap-1 font-mono">
            <span className="text-threat-critical">● {criticalCount} Critical</span> | <span className="text-threat-high">{highCount} High</span>
          </div>
        </Card>

        {/* Metric 3 */}
        <Card className="bg-soc-900/90 border-soc-800">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-medium text-soc-400 uppercase">Blockchain Integrity</span>
            <Link2 className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-cyan-300">
              {loading ? '...' : `${verifiedPercentage}%`}
            </span>
            <span className="text-[11px] text-soc-500 font-mono">({blockchainVerifiedCount}/{totalCases})</span>
          </div>
          <div className="mt-2 text-[11px] text-soc-400 flex items-center gap-1 font-mono">
            <span className="text-emerald-400">SHA-256</span> cryptographic proofs
          </div>
        </Card>

        {/* Metric 4 */}
        <Card className="bg-soc-900/90 border-soc-800">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-medium text-soc-400 uppercase">Mean Analysis Latency</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-soc-100">
              {stats ? `${stats.mean_latency_seconds}s` : '1.2s'}
            </span>
            <span className="text-[11px] text-soc-500 font-mono">/ CASE</span>
          </div>
          <div className="mt-2 text-[11px] text-soc-400 flex items-center gap-1 font-mono">
            <span className="text-emerald-400">Zero Execution</span> sandbox parsing
          </div>
        </Card>
      </div>

      {/* Error Banner if API connection fails */}
      {error && (
        <div className="p-3 bg-red-950/50 border border-red-800/80 rounded flex items-center gap-3 text-xs text-red-300 font-mono">
          <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <div className="flex-1">
            <strong>BACKEND_COMMUNICATION_ERROR:</strong> {error}
          </div>
        </div>
      )}

      {/* Main Grid: Active Investigations Table + Forensic Integrity Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Active Investigations Table */}
        <div className="lg:col-span-2 space-y-4">
          <Card
            title="Active Forensic Investigations"
            subtitle="Prioritized case queue sorted by risk score and IOC severity"
            action={
              <Link
                to="/investigations/active"
                className="text-xs text-blue-400 hover:text-blue-300 font-mono flex items-center gap-1"
              >
                View Full Queue <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            }
            noPadding
          >
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-soc-800 text-[11px] font-mono text-soc-400 uppercase bg-soc-950/40">
                    <th className="px-4 py-2.5">Case ID</th>
                    <th className="px-4 py-2.5">Threat Classification</th>
                    <th className="px-4 py-2.5">Suspect Sender</th>
                    <th className="px-4 py-2.5 text-center">Score</th>
                    <th className="px-4 py-2.5">Status</th>
                    <th className="px-4 py-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-800/60 text-xs">
                  {loading ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-soc-500 font-mono">
                        Loading investigation dataset from API...
                      </td>
                    </tr>
                  ) : investigations.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-soc-500 font-mono">
                        No active investigations found. Upload a .EML in the Email Analyzer to begin.
                      </td>
                    </tr>
                  ) : (
                    investigations.map((item) => (
                      <tr
                        key={item.id}
                        onClick={() => navigate(`/investigations/${item.id}`)}
                        className="hover:bg-soc-850/50 transition-colors cursor-pointer"
                      >
                        <td className="px-4 py-3 font-mono font-medium text-blue-400 whitespace-nowrap">
                          {item.id}
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-soc-200">{item.title}</div>
                          <div className="text-[11px] text-soc-500 truncate max-w-xs">{item.subject}</div>
                        </td>
                        <td className="px-4 py-3 font-mono text-[11px] text-soc-400 whitespace-nowrap">
                          {item.sender}
                        </td>
                        <td className="px-4 py-3 text-center whitespace-nowrap">
                          <Badge variant="severity" severity={item.severity as ThreatSeverity}>
                            {item.threat_score}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <Badge variant="status" status={item.status}>
                            {item.status}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-right whitespace-nowrap">
                          <Link
                            to={`/investigations/${item.id}`}
                            className="inline-flex items-center gap-1 text-[11px] font-mono text-soc-400 hover:text-soc-100 px-2.5 py-1 bg-soc-800 rounded border border-soc-700 hover:border-soc-600 transition-colors"
                          >
                            <span>Inspect</span>
                            <ExternalLink className="w-3 h-3" />
                          </Link>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>

          {/* Classification Breakdown Panel */}
          {stats && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
              <Card title="Threat Classification Distribution">
                <div className="space-y-2">
                  {Object.entries(stats.classification_breakdown).map(([key, val]) => (
                    <div key={key} className="flex items-center justify-between text-xs py-1 border-b border-soc-800/60">
                      <span className="text-soc-300">{key.replace(/_/g, ' ')}</span>
                      <span className="text-blue-400 font-bold">{val} cases</span>
                    </div>
                  ))}
                </div>
              </Card>

              <Card title="Top Observed Domains">
                <div className="space-y-2">
                  {stats.top_domains.map((dom, idx) => (
                    <div key={idx} className="flex items-center justify-between text-xs py-1 border-b border-soc-800/60">
                      <span className="text-soc-200 truncate max-w-[160px]">{dom.domain}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-soc-500">{dom.type}</span>
                        <span className={`text-[10px] font-bold ${dom.risk === 'CRITICAL' ? 'text-red-400' : 'text-emerald-400'}`}>
                          {dom.risk}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          )}

          {/* AI SOC Analyst Threat Correlation Matrix */}
          <Card
            title="AI SOC Analyst — Multi-Entity Correlation & MITRE TTPs"
            subtitle="Cross-case pattern recognition, prompt-injection defense & deterministic alignment"
            action={
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-soc-800 text-purple-300 border border-purple-500/30 flex items-center gap-1">
                <Cpu className="w-3 h-3 text-purple-400" />
                <span>AI_HYBRID_ENGINE // ACTIVE</span>
              </span>
            }
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
              <div className="p-3 bg-soc-950/60 border border-soc-800 rounded">
                <div className="text-soc-400 text-[10px] uppercase font-semibold">Correlated Threat Clusters</div>
                <div className="text-lg font-bold text-soc-100 mt-1">3 Clusters</div>
                <div className="text-[11px] text-soc-500 mt-0.5">BEC · Credential Theft · Phishing</div>
              </div>
              <div className="p-3 bg-soc-950/60 border border-soc-800 rounded">
                <div className="text-soc-400 text-[10px] uppercase font-semibold">Active MITRE ATT&CK TTPs</div>
                <div className="text-lg font-bold text-purple-300 mt-1">5 Mappings</div>
                <div className="text-[11px] text-soc-500 mt-0.5">T1566.001, T1566.002, T1583</div>
              </div>
              <div className="p-3 bg-soc-950/60 border border-soc-800 rounded">
                <div className="text-soc-400 text-[10px] uppercase font-semibold">Evidence Integrity Gate</div>
                <div className="text-lg font-bold text-emerald-400 mt-1">Enforced</div>
                <div className="text-[11px] text-soc-500 mt-0.5">Deterministic Rules &gt; AI Interpretation</div>
              </div>
            </div>
          </Card>
        </div>

        {/* Right 1 Col: Evidence Integrity & Blockchain Activity Ledger */}
        <div className="space-y-4">
          <Card
            title="Evidence Integrity Ledger"
            subtitle="SHA-256 Hashes Anchored to Immutable Chain"
            action={
              <Link
                to="/blockchain/verification"
                className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
              >
                Verify <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            }
          >
            <div className="space-y-3">
              {investigations.slice(0, 4).map((inv) => (
                <div
                  key={inv.id}
                  onClick={() => navigate(`/investigations/${inv.id}`)}
                  className="p-2.5 bg-soc-950/60 border border-soc-800 hover:border-soc-700 rounded text-xs space-y-1.5 font-mono cursor-pointer transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-blue-400 font-semibold">{inv.id}</span>
                    {inv.blockchain_verified ? (
                      <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400">
                        <FileCheck className="w-3 h-3" /> ANCHORED
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] text-soc-500">
                        <Clock className="w-3 h-3" /> PENDING
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-soc-400 truncate flex items-center gap-1">
                    <Hash className="w-3 h-3 text-soc-600 flex-shrink-0" />
                    <span className="font-mono text-soc-300 select-all">{inv.evidence_hash}</span>
                  </div>
                  <div className="text-[10px] text-soc-600 flex items-center justify-between">
                    <span>Target: EML_FORENSIC_SNAPSHOT</span>
                    <span>{new Date(inv.created_at).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* Top Source IPs Card */}
          {stats && (
            <Card title="Top Suspect Source IPs">
              <div className="space-y-2 font-mono text-xs">
                {stats.top_source_ips.map((item, idx) => (
                  <div key={idx} className="flex items-center justify-between py-1.5 border-b border-soc-800/60">
                    <span className="text-soc-200">{item.ip}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-soc-500">{item.country}</span>
                      <span className={`text-[10px] font-bold ${item.threat === 'HIGH' ? 'text-red-400' : 'text-soc-400'}`}>
                        {item.threat}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Core Architecture Notice */}
          <div className="p-3.5 bg-soc-900 border border-soc-800 rounded text-xs text-soc-400 space-y-2 font-mono">
            <div className="text-soc-200 font-semibold flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-blue-400" />
              <span>CORE FORENSIC GUARD</span>
            </div>
            <p className="text-[11px] leading-relaxed text-soc-400">
              Raw email payloads are never written on-chain. Only deterministic SHA-256 evidence digests are preserved for evidentiary integrity and compliance audits.
            </p>
          </div>
        </div>
      </div>

      <NewInvestigationModal
        isOpen={isNewModalOpen}
        onClose={() => setIsNewModalOpen(false)}
      />
    </div>
  );
};
