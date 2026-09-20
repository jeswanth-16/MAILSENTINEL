import React, { useEffect, useState } from 'react';
import { Badge } from '../components/common/Badge';
import { InvestigationSummary, ThreatSeverity } from '../types/investigation';
import {
  fetchInvestigations,
  runFullInvestigation,
} from '../services/investigationService';
import {
  FolderLock,
  Search,
  Hash,
  ArrowRight,
  Zap,
  CheckCircle2,
  RefreshCw,
  FileCheck,
} from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';

export const ActiveCasesPage: React.FC = () => {
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // Full Investigation Runner Modal
  const [showRunModal, setShowRunModal] = useState<boolean>(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analystName, setAnalystName] = useState<string>('SOC-L2-ANALYST');
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [runSteps, setRunSteps] = useState<string[]>([]);
  const [runError, setRunError] = useState<string | null>(null);

  useEffect(() => {
    loadCases();
  }, []);

  async function loadCases() {
    try {
      setLoading(true);
      const data = await fetchInvestigations();
      setInvestigations(data.investigations);
    } catch (e: any) {
      console.error('Failed to load investigations:', e);
    } finally {
      setLoading(false);
    }
  }

  const filtered = investigations.filter((i) => {
    const matchesSearch =
      i.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      i.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      i.sender.toLowerCase().includes(searchTerm.toLowerCase()) ||
      i.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (i.classification && i.classification.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesSeverity =
      severityFilter === 'ALL' || i.severity.toUpperCase() === severityFilter.toUpperCase();

    const matchesStatus =
      statusFilter === 'ALL' || i.status.toUpperCase() === statusFilter.toUpperCase();

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  async function handleStartFullInvestigation() {
    if (!selectedFile) return;
    try {
      setIsRunning(true);
      setRunError(null);
      setRunSteps([
        'Ingesting .EML message payload into secure memory sandbox...',
        'Parsing RFC 5322 headers and MIME boundary attachments...',
        'Evaluating cryptographic SPF, DKIM, and DMARC alignment...',
        'Executing deterministic threat rule and IOC detection engine...',
        'Calculating explainable risk score and threat classification...',
        'Correlating IPs, domains, and URLs with threat intelligence feeds...',
        'Synthesizing chronological forensic timeline and attack graph...',
        'Generating canonical evidence package and SHA-256 fingerprint...',
        'Anchoring evidence digest to MAILSENTINEL blockchain ledger...',
        'Registering verified case in unified SOC investigation registry...',
      ]);

      const res = await runFullInvestigation(selectedFile, analystName);
      setTimeout(() => {
        setIsRunning(false);
        setShowRunModal(false);
        navigate(`/investigations/${res.investigation.id}`);
      }, 1500);
    } catch (err: any) {
      setIsRunning(false);
      setRunError(err.message || 'Error running full investigation pipeline');
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <FolderLock className="w-5 h-5 text-blue-400" />
            <span>INVESTIGATIONS_QUEUE // ACTIVE_CASES</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Real-time unified queue of active digital forensics and threat triage cases.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowRunModal(true)}
            className="px-3.5 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold font-mono flex items-center gap-1.5 transition-colors shadow-lg shadow-blue-900/40"
          >
            <Zap className="w-3.5 h-3.5 text-yellow-300" />
            <span>Run Full Investigation</span>
          </button>

          <Link
            to="/analysis/email"
            className="px-3 py-1.5 rounded bg-soc-800 hover:bg-soc-700 text-soc-200 text-xs font-semibold font-mono border border-soc-700 transition-colors"
          >
            + Ingest Raw .EML
          </Link>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-soc-900 p-3.5 border border-soc-800 rounded-md">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-soc-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by Case ID, subject, sender, or classification..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-soc-950 border border-soc-800 rounded text-soc-200 placeholder-soc-600 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="text-soc-500">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-soc-950 border border-soc-800 text-soc-200 px-2 py-1 rounded text-xs focus:outline-none"
            >
              <option value="ALL">ALL</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="CLEAN">CLEAN</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-soc-500">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-soc-950 border border-soc-800 text-soc-200 px-2 py-1 rounded text-xs focus:outline-none"
            >
              <option value="ALL">ALL</option>
              <option value="NEW">NEW</option>
              <option value="TRIAGING">TRIAGING</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="CONTAINED">CONTAINED</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
            </select>
          </div>

          <div className="text-soc-400 font-mono text-[11px] pl-2 border-l border-soc-800">
            <span>{filtered.length} Cases</span>
          </div>
        </div>
      </div>

      {/* Cases List */}
      <div className="space-y-3">
        {loading ? (
          <div className="p-12 text-center text-xs font-mono text-soc-500 bg-soc-900 border border-soc-800 rounded">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-blue-400" />
            <span>Loading active investigations from registry...</span>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-xs font-mono text-soc-500 bg-soc-900 border border-soc-800 rounded">
            No matching active investigations found.
          </div>
        ) : (
          filtered.map((c) => (
            <div
              key={c.id}
              onClick={() => navigate(`/investigations/${c.id}`)}
              className="p-4 bg-soc-900 border border-soc-800 hover:border-soc-700 hover:bg-soc-850/60 rounded-md transition-all cursor-pointer space-y-3 shadow-sm"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm font-bold text-blue-400">{c.id}</span>
                  <Badge variant="severity" severity={c.severity as ThreatSeverity}>
                    RISK: {c.threat_score} ({c.severity})
                  </Badge>
                  <Badge variant="status" status={c.status}>
                    {c.status}
                  </Badge>
                  {c.blockchain_verified && (
                    <span className="inline-flex items-center gap-1 text-[10px] font-mono text-emerald-400 px-2 py-0.5 rounded bg-emerald-950/40 border border-emerald-800/60">
                      <FileCheck className="w-3 h-3" /> ANCHORED
                    </span>
                  )}
                </div>
                <div className="text-[11px] font-mono text-soc-500">
                  Updated: {new Date(c.updated_at).toLocaleString()}
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-soc-100">{c.title}</h3>
                <p className="text-xs text-soc-400 mt-0.5">
                  Subject: <span className="text-soc-300">{c.subject}</span>
                </p>
                <p className="text-xs font-mono text-soc-500 mt-0.5">
                  Sender: <span className="text-soc-300">{c.sender}</span>
                </p>
              </div>

              <div className="pt-2 border-t border-soc-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
                <div className="flex items-center gap-2 text-soc-500 text-[11px] truncate max-w-lg">
                  <Hash className="w-3.5 h-3.5 text-soc-600 flex-shrink-0" />
                  <span className="truncate">{c.evidence_hash}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-[11px] text-soc-400">
                    Analyst: <span className="text-soc-200">{c.analyst}</span>
                  </span>
                  <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-soc-800 hover:bg-soc-700 text-soc-200 rounded border border-soc-700 text-xs font-mono transition-colors">
                    <span>Open Workbench</span>
                    <ArrowRight className="w-3 h-3" />
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* FULL INVESTIGATION DEMO MODAL */}
      {showRunModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 font-mono">
          <div className="w-full max-w-lg bg-soc-900 border border-soc-700 rounded-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-soc-800 pb-3">
              <h3 className="text-sm font-bold text-soc-100 flex items-center gap-2">
                <Zap className="w-4 h-4 text-yellow-400" />
                <span>Automated SOC Investigation Pipeline</span>
              </h3>
              {!isRunning && (
                <button
                  onClick={() => setShowRunModal(false)}
                  className="text-soc-500 hover:text-soc-300 text-xs"
                >
                  ✕
                </button>
              )}
            </div>

            {!isRunning ? (
              <div className="space-y-4 text-xs">
                <p className="text-soc-300 leading-relaxed">
                  Upload any RFC 5322 <code className="text-blue-400">.EML</code> file to execute the full automated cybersecurity pipeline: parsing, threat scoring, geolocation, attack graph, evidence packaging, and blockchain anchoring.
                </p>

                <div className="space-y-1.5">
                  <label className="text-soc-400 block font-semibold">Select Target .EML File:</label>
                  <input
                    type="file"
                    accept=".eml,.msg,.txt,.mail"
                    onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                    className="w-full px-3 py-2 bg-soc-950 border border-soc-800 rounded text-soc-200 text-xs focus:outline-none"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-soc-400 block font-semibold">Assigned Analyst:</label>
                  <input
                    type="text"
                    value={analystName}
                    onChange={(e) => setAnalystName(e.target.value)}
                    className="w-full px-3 py-1.5 bg-soc-950 border border-soc-800 rounded text-soc-200 text-xs focus:outline-none"
                  />
                </div>

                {runError && (
                  <div className="p-2.5 bg-red-950/60 border border-red-800 rounded text-red-300 text-[11px]">
                    {runError}
                  </div>
                )}

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={() => setShowRunModal(false)}
                    className="px-3 py-1.5 bg-soc-800 text-soc-300 rounded hover:bg-soc-700"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleStartFullInvestigation}
                    disabled={!selectedFile}
                    className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-semibold disabled:opacity-50 flex items-center gap-1.5"
                  >
                    <Zap className="w-3.5 h-3.5 text-yellow-300" />
                    <span>Run Full Pipeline</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-3 text-xs">
                <div className="flex items-center gap-2 text-blue-400 font-semibold mb-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Executing End-to-End SOC Triage Workflow...</span>
                </div>

                <div className="space-y-2 bg-soc-950 p-3 rounded border border-soc-800 max-h-60 overflow-y-auto">
                  {runSteps.map((step, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-[11px] text-soc-300">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
