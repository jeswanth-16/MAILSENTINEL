import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Badge } from '../components/common/Badge';
import { Card } from '../components/common/Card';
import {
  Investigation,
  InvestigationOverview,
  ThreatSeverity,
} from '../types/investigation';
import { AIAnalystAssessment } from '../types/ai';
import {
  fetchInvestigation,
  fetchInvestigationOverview,
  addInvestigationNote,
  deleteInvestigationNote,
  assignAnalyst,
  updateInvestigationStatus,
  escalateInvestigation,
} from '../services/investigationService';
import {
  fetchAIAssessment,
  refreshAIAssessment,
} from '../services/aiService';
import {
  getInvestigationCorrelation,
} from '../services/intelligenceService';
import {
  IndicatorCorrelationResult,
} from '../types/intelligence';
import {
  verifyEvidence,
  simulateTamper,
  resetTamper,
} from '../services/blockchainService';
import {
  ShieldAlert,
  AlertTriangle,
  FolderLock,
  UserCheck,
  ArrowRight,
  ExternalLink,
  FileCheck,
  FileWarning,
  Flame,
  FileText,
  Activity,
  RefreshCw,
  Check,
  Plus,
  Cpu,
  Trash2,
  Copy,
  Printer,
} from 'lucide-react';

export const InvestigationWorkbenchPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const caseId = id || 'INV-2026-00001';

  const [activeTab, setActiveTab] = useState<string>('OVERVIEW');
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [overview, setOverview] = useState<InvestigationOverview | null>(null);
  const [aiAssessment, setAiAssessment] = useState<AIAnalystAssessment | null>(null);
  const [correlation, setCorrelation] = useState<IndicatorCorrelationResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [aiLoading, setAiLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Modals / Quick Actions State
  const [showAssignModal, setShowAssignModal] = useState<boolean>(false);
  const [showStatusModal, setShowStatusModal] = useState<boolean>(false);
  const [showEscalateModal, setShowEscalateModal] = useState<boolean>(false);
  const [showNoteModal, setShowNoteModal] = useState<boolean>(false);

  // Form Inputs
  const [newAnalystName, setNewAnalystName] = useState<string>('');
  const [newStatusValue, setNewStatusValue] = useState<string>('INVESTIGATING');
  const [statusReason, setStatusReason] = useState<string>('');
  const [escalateReason, setEscalateReason] = useState<string>('');
  const [noteContent, setNoteContent] = useState<string>('');
  const [noteType, setNoteType] = useState<string>('NOTE');

  // Blockchain Live Verification State
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [isTampering, setIsTampering] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  useEffect(() => {
    loadCaseData();
  }, [caseId]);

  async function loadCaseData() {
    try {
      setLoading(true);
      setError(null);
      const [caseData, overviewData, aiData, corrData] = await Promise.all([
        fetchInvestigation(caseId),
        fetchInvestigationOverview(caseId),
        fetchAIAssessment(caseId).catch(() => null),
        getInvestigationCorrelation(caseId).catch(() => null),
      ]);
      setInvestigation(caseData);
      setOverview(overviewData);
      setAiAssessment(aiData);
      setCorrelation(corrData);
    } catch (err: any) {
      setError(err.message || `Failed to load investigation ${caseId}`);
    } finally {
      setLoading(false);
    }
  }

  async function handleRefreshAI() {
    try {
      setAiLoading(true);
      const freshAi = await refreshAIAssessment(caseId);
      setAiAssessment(freshAi);
      setActionMessage('AI Analyst assessment and multi-entity correlation refreshed.');
    } catch (err: any) {
      alert(err.message || 'Failed to refresh AI analysis');
    } finally {
      setAiLoading(false);
    }
  }

  async function handleAssignSubmit() {
    if (!newAnalystName.trim()) return;
    try {
      await assignAnalyst(caseId, newAnalystName.trim());
      setShowAssignModal(false);
      setNewAnalystName('');
      setActionMessage(`Case successfully assigned to ${newAnalystName}`);
      loadCaseData();
    } catch (e: any) {
      alert(e.message || 'Failed to assign analyst');
    }
  }

  async function handleStatusSubmit() {
    try {
      await updateInvestigationStatus(caseId, newStatusValue, statusReason);
      setShowStatusModal(false);
      setStatusReason('');
      setActionMessage(`Case status updated to ${newStatusValue}`);
      loadCaseData();
    } catch (e: any) {
      alert(e.message || 'Failed to update status');
    }
  }

  async function handleEscalateSubmit() {
    if (!escalateReason.trim()) return;
    try {
      await escalateInvestigation(caseId, escalateReason);
      setShowEscalateModal(false);
      setEscalateReason('');
      setActionMessage('Case escalated to Tier 3 Incident Response.');
      loadCaseData();
    } catch (e: any) {
      alert(e.message || 'Failed to escalate');
    }
  }

  async function handleAddNoteSubmit() {
    if (!noteContent.trim()) return;
    try {
      await addInvestigationNote(caseId, noteContent.trim(), 'SOC Analyst', noteType);
      setShowNoteModal(false);
      setNoteContent('');
      setActionMessage('Analyst note appended to audit trail.');
      loadCaseData();
    } catch (e: any) {
      alert(e.message || 'Failed to add note');
    }
  }

  async function handleDeleteNote(noteId: string) {
    try {
      await deleteInvestigationNote(caseId, noteId);
      setActionMessage('Analyst note removed from case audit log.');
      loadCaseData();
    } catch (e: any) {
      alert(e.message || 'Failed to delete note');
    }
  }

  function handleCopyHash(hashText: string) {
    navigator.clipboard.writeText(hashText);
    setActionMessage('SHA-256 evidence fingerprint copied to clipboard.');
  }

  async function handleVerifyBlockchain() {
    if (!investigation?.evidence_id) return;
    try {
      setIsVerifying(true);
      const res = await verifyEvidence(investigation.evidence_id);
      setVerificationResult(res);
      setActionMessage(`Integrity check: ${res.status}`);
      loadCaseData();
    } catch (e: any) {
      alert(e.message || 'Failed to verify blockchain integrity');
    } finally {
      setIsVerifying(false);
    }
  }

  async function handleSimulateTamper() {
    if (!investigation?.evidence_id) return;
    try {
      setIsTampering(true);
      await simulateTamper(investigation.evidence_id);
      const res = await verifyEvidence(investigation.evidence_id);
      setVerificationResult(res);
      setActionMessage('Simulated unauthorized evidence alteration in memory.');
      loadCaseData();
    } catch (e: any) {
      alert(e.message || 'Failed to simulate tampering');
    } finally {
      setIsTampering(false);
    }
  }

  async function handleResetTamper() {
    if (!investigation?.evidence_id) return;
    try {
      setIsTampering(true);
      await resetTamper(investigation.evidence_id);
      const res = await verifyEvidence(investigation.evidence_id);
      setVerificationResult(res);
      setActionMessage('Restored original canonical evidence package.');
      loadCaseData();
    } catch (e: any) {
      alert(e.message || 'Failed to reset tampering');
    } finally {
      setIsTampering(false);
    }
  }

  if (loading) {
    return (
      <div className="p-16 text-center text-xs font-mono text-soc-400 bg-soc-900 border border-soc-800 rounded">
        <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-3 text-blue-400" />
        <span>Loading unified investigation workspace for {caseId}...</span>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="p-8 bg-red-950/40 border border-red-800/80 rounded font-mono text-xs text-red-300 space-y-4">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          <span className="font-bold">INVESTIGATION_LOAD_ERROR</span>
        </div>
        <p>{error || 'Investigation not found.'}</p>
        <Link
          to="/investigations/active"
          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-soc-800 text-soc-200 rounded border border-soc-700 hover:bg-soc-700 transition-colors"
        >
          <span>Return to Active Investigations Queue</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Toast Notification Banner */}
      {actionMessage && (
        <div className="p-2.5 bg-blue-950/70 border border-blue-800 rounded flex items-center justify-between text-xs font-mono text-blue-200">
          <span>● {actionMessage}</span>
          <button
            onClick={() => setActionMessage(null)}
            className="text-blue-400 hover:text-blue-200 text-[11px]"
          >
            DISMISS
          </button>
        </div>
      )}

      {/* Top Header & Case Command Banner */}
      <div className="bg-soc-900 border border-soc-800 rounded-md p-5 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-soc-800/80 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 font-mono text-xs text-soc-500">
              <Link to="/investigations/active" className="hover:text-blue-400 transition-colors">
                INVESTIGATIONS
              </Link>
              <span>/</span>
              <span className="text-blue-400 font-bold">{investigation.id}</span>
              <span>({investigation.case_number})</span>
            </div>
            <h1 className="text-lg font-bold text-soc-100 flex items-center gap-2">
              <FolderLock className="w-5 h-5 text-blue-400 flex-shrink-0" />
              <span>{investigation.title}</span>
            </h1>
            <p className="text-xs text-soc-400 font-mono">
              Source: <span className="text-soc-300">{investigation.source}</span> | Sender: <span className="text-soc-200">{investigation.sender}</span>
            </p>
          </div>

          {/* Key Metrics / Risk Score Card */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3 bg-soc-950 px-4 py-2 rounded border border-soc-800">
              <div className="text-right">
                <span className="text-[10px] text-soc-500 font-mono block uppercase">Threat Risk</span>
                <span
                  className={`text-xl font-mono font-bold ${
                    investigation.risk_score >= 80
                      ? 'text-threat-critical'
                      : investigation.risk_score >= 50
                      ? 'text-threat-high'
                      : investigation.risk_score >= 20
                      ? 'text-threat-medium'
                      : 'text-emerald-400'
                  }`}
                >
                  {investigation.risk_score} <span className="text-xs text-soc-500">/ 100</span>
                </span>
              </div>
              <div className="h-8 w-px bg-soc-800" />
              <div>
                <span className="text-[10px] text-soc-500 font-mono block uppercase">Detection Conf.</span>
                <span className="text-sm font-mono font-bold text-soc-200">
                  {investigation.confidence}%
                </span>
              </div>
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-1.5">
                <Badge variant="severity" severity={investigation.severity}>
                  {investigation.severity}
                </Badge>
                <Badge variant="status" status={investigation.status}>
                  {investigation.status}
                </Badge>
              </div>
              <div className="text-[10px] font-mono text-soc-500">
                Classification: <span className="text-soc-300">{investigation.classification}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setShowAssignModal(true)}
              className="px-3 py-1.5 rounded bg-soc-800 hover:bg-soc-700 text-soc-200 border border-soc-700 flex items-center gap-1.5 transition-colors"
            >
              <UserCheck className="w-3.5 h-3.5 text-blue-400" />
              <span>Assign ({investigation.assigned_analyst})</span>
            </button>

            <button
              onClick={() => setShowStatusModal(true)}
              className="px-3 py-1.5 rounded bg-soc-800 hover:bg-soc-700 text-soc-200 border border-soc-700 flex items-center gap-1.5 transition-colors"
            >
              <Activity className="w-3.5 h-3.5 text-amber-400" />
              <span>Change Status</span>
            </button>

            <button
              onClick={() => setShowEscalateModal(true)}
              className="px-3 py-1.5 rounded bg-red-950/50 hover:bg-red-900/50 text-red-300 border border-red-800/80 flex items-center gap-1.5 transition-colors"
            >
              <Flame className="w-3.5 h-3.5 text-red-400" />
              <span>Escalate Case</span>
            </button>

            <button
              onClick={() => setShowNoteModal(true)}
              className="px-3 py-1.5 rounded bg-soc-800 hover:bg-soc-700 text-soc-200 border border-soc-700 flex items-center gap-1.5 transition-colors"
            >
              <Plus className="w-3.5 h-3.5 text-emerald-400" />
              <span>Add Note</span>
            </button>
          </div>

          <div className="flex items-center gap-2">
            <Link
              to="/reports"
              className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export Dossier</span>
            </Link>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="border-b border-soc-800 flex items-center gap-1 overflow-x-auto text-xs font-mono">
        {[
          { id: 'OVERVIEW', label: 'Overview & Triage' },
          { id: 'EVIDENCE', label: 'Evidence Package' },
          { id: 'FORENSICS', label: 'Email Forensics' },
          { id: 'THREAT', label: 'Threat & Risk Engine' },
          { id: 'AI_ANALYST', label: '⚡ Forensic Decision Engine', highlight: true },
          { id: 'INTELLIGENCE', label: 'Intelligence & GeoIP' },
          { id: 'TIMELINE', label: 'Timeline' },
          { id: 'GRAPH', label: 'Attack Graph' },
          { id: 'BLOCKCHAIN', label: 'Blockchain Integrity' },
          { id: 'REPORT', label: 'Verdict & Report' },
          { id: 'NOTES', label: `Notes & Audit (${investigation.notes.length})` },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2.5 font-medium whitespace-nowrap border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-blue-500 text-blue-400 bg-soc-900/50'
                : tab.highlight
                ? 'border-transparent text-yellow-300 hover:text-yellow-200 hover:bg-yellow-950/20'
                : 'border-transparent text-soc-400 hover:text-soc-200 hover:bg-soc-900/30'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* TAB CONTENT: 1. OVERVIEW */}
      {activeTab === 'OVERVIEW' && (
        <div className="space-y-6">
          {/* Executive Verdict Banner */}
          <div className="p-4 bg-soc-900 border border-soc-800 rounded-md space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-soc-400 uppercase font-bold flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-threat-critical" />
                <span>Executive Verdict & Threat Narrative</span>
              </span>
              <span className="text-[11px] font-mono text-soc-500">
                Created: {new Date(investigation.created_at).toLocaleString()}
              </span>
            </div>
            <p className="text-sm text-soc-200 leading-relaxed">
              {investigation.verdict_summary || investigation.description}
            </p>
          </div>

          {/* Side-by-Side Forensic Evidence vs Analyst Assessment */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left: Original Observed Evidence */}
            <Card
              title="Original Observed Evidence"
              subtitle="Cryptographically verified email headers & entity extractions"
            >
              <div className="space-y-3 text-xs font-mono">
                <div className="p-2.5 bg-soc-950 border border-soc-800 rounded space-y-1">
                  <span className="text-soc-500 text-[11px] block">Sender (From Header)</span>
                  <span className="text-soc-100 font-semibold select-all">{investigation.sender}</span>
                </div>

                <div className="p-2.5 bg-soc-950 border border-soc-800 rounded space-y-1">
                  <span className="text-soc-500 text-[11px] block">Subject</span>
                  <span className="text-soc-200">{investigation.subject}</span>
                </div>

                {/* Authentication Matrix */}
                <div className="p-2.5 bg-soc-950 border border-soc-800 rounded space-y-2">
                  <span className="text-soc-500 text-[11px] block">Cryptographic Authentication</span>
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="p-1.5 bg-soc-900 border border-soc-800 rounded">
                      <span className="text-[10px] text-soc-500 block">SPF</span>
                      <span className={`font-bold ${overview?.auth_summary.spf === 'PASS' ? 'text-emerald-400' : 'text-red-400'}`}>
                        {overview?.auth_summary.spf || 'N/A'}
                      </span>
                    </div>
                    <div className="p-1.5 bg-soc-900 border border-soc-800 rounded">
                      <span className="text-[10px] text-soc-500 block">DKIM</span>
                      <span className={`font-bold ${overview?.auth_summary.dkim === 'PASS' ? 'text-emerald-400' : 'text-red-400'}`}>
                        {overview?.auth_summary.dkim || 'N/A'}
                      </span>
                    </div>
                    <div className="p-1.5 bg-soc-900 border border-soc-800 rounded">
                      <span className="text-[10px] text-soc-500 block">DMARC</span>
                      <span className={`font-bold ${overview?.auth_summary.dmarc === 'PASS' ? 'text-emerald-400' : 'text-red-400'}`}>
                        {overview?.auth_summary.dmarc || 'N/A'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Extracted Entities Counter */}
                <div className="grid grid-cols-4 gap-2 text-center">
                  <div className="p-2 bg-soc-950 border border-soc-800 rounded">
                    <span className="text-[10px] text-soc-500 block">IPs</span>
                    <span className="font-bold text-soc-200">{overview?.top_entities.ips_count || 0}</span>
                  </div>
                  <div className="p-2 bg-soc-950 border border-soc-800 rounded">
                    <span className="text-[10px] text-soc-500 block">Domains</span>
                    <span className="font-bold text-soc-200">{overview?.top_entities.domains_count || 0}</span>
                  </div>
                  <div className="p-2 bg-soc-950 border border-soc-800 rounded">
                    <span className="text-[10px] text-soc-500 block">URLs</span>
                    <span className="font-bold text-soc-200">{overview?.top_entities.urls_count || 0}</span>
                  </div>
                  <div className="p-2 bg-soc-950 border border-soc-800 rounded">
                    <span className="text-[10px] text-soc-500 block">Files</span>
                    <span className="font-bold text-soc-200">{overview?.top_entities.attachments_count || 0}</span>
                  </div>
                </div>
              </div>
            </Card>

            {/* Right: Analyst Assessment & Defensive Signals */}
            <Card
              title="Threat Assessment & Actionable Guidance"
              subtitle="Deterministic risk scoring breakdown & recommended containment steps"
            >
              <div className="space-y-4 text-xs font-mono">
                {/* Key Findings List */}
                <div className="space-y-2">
                  <span className="text-soc-400 font-semibold uppercase text-[11px] block">
                    Top Contributing Indicators:
                  </span>
                  <div className="space-y-1.5">
                    {overview?.key_findings.map((finding, idx) => (
                      <div
                        key={idx}
                        className="p-2 bg-soc-950 border border-soc-800 rounded flex items-start gap-2 text-soc-300"
                      >
                        <span className="text-threat-critical">●</span>
                        <span>{finding}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recommended Containment Actions */}
                <div className="space-y-2">
                  <span className="text-soc-400 font-semibold uppercase text-[11px] block">
                    Defensive Containment Actions:
                  </span>
                  <div className="space-y-1.5">
                    {investigation.recommended_actions.map((act, idx) => (
                      <div
                        key={idx}
                        className="p-2 bg-blue-950/30 border border-blue-800/60 rounded flex items-start gap-2 text-blue-200 text-[11px]"
                      >
                        <Check className="w-3.5 h-3.5 text-blue-400 flex-shrink-0 mt-0.5" />
                        <span>{act}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 2. EVIDENCE PACKAGE */}
      {activeTab === 'EVIDENCE' && (
        <div className="space-y-6 font-mono text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card title="Observed Evidence Ingestion Provenance">
              <div className="space-y-3">
                <div className="flex justify-between py-1 border-b border-soc-800">
                  <span className="text-soc-500">Evidence ID</span>
                  <span className="text-blue-400 font-bold">{investigation.evidence_id || 'EVD-2026-00001'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-800">
                  <span className="text-soc-500">MIME Container</span>
                  <span className="text-soc-200">message/rfc822 (.eml)</span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-800">
                  <span className="text-soc-500">Ingestion Source</span>
                  <span className="text-soc-200">{investigation.source}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-800">
                  <span className="text-soc-500">Ingestion Timestamp</span>
                  <span className="text-soc-300">{new Date(investigation.created_at).toISOString()}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-800">
                  <span className="text-soc-500">Canonical Packaging</span>
                  <span className="text-emerald-400">RFC 8785 JSON Canonicalization</span>
                </div>
              </div>
            </Card>

            <Card title="Authoritative SHA-256 Fingerprint">
              <div className="space-y-3">
                <p className="text-soc-400 text-[11px]">
                  Deterministic cryptographic digest computed over canonical forensic artifacts:
                </p>
                <div className="p-2.5 bg-soc-950 border border-soc-800 rounded flex items-center justify-between gap-2">
                  <span className="text-soc-200 truncate select-all text-[11px]">{investigation.evidence_hash}</span>
                  <button
                    onClick={() => handleCopyHash(investigation.evidence_hash)}
                    title="Copy SHA-256 Digest"
                    className="p-1 rounded bg-soc-800 hover:bg-soc-700 text-soc-300 flex-shrink-0"
                  >
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="p-3 bg-soc-950/60 border border-soc-800 rounded space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-soc-400 text-[10px] uppercase font-semibold">Integrity Status</span>
                    <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-bold">
                      <FileCheck className="w-3.5 h-3.5" />
                      <span>{investigation.blockchain_verified ? 'CRYPTOGRAPHICALLY ANCHORED' : 'PENDING ON-CHAIN SYNC'}</span>
                    </span>
                  </div>
                  <div className="text-[10px] text-soc-500">
                    Network: <span className="text-soc-300">{investigation.blockchain_network || 'MAILSENTINEL-DEMO-CHAIN'}</span> | Block #{investigation.blockchain_block || 1042}
                  </div>
                </div>
              </div>
            </Card>
          </div>

          {/* Privacy Guard Notice */}
          <div className="p-3.5 bg-soc-900 border border-soc-800 rounded text-xs text-soc-400 space-y-1.5">
            <div className="text-soc-200 font-semibold flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-blue-400" />
              <span>Digital Forensics Privacy & Evidence Admissibility Guard</span>
            </div>
            <p className="text-[11px] leading-relaxed text-soc-400">
              In accordance with forensic chain-of-custody standards (ISO/IEC 27037), raw email bodies and sensitive PII are never committed to the public blockchain ledger. Only immutable SHA-256 evidence digests and custody timestamps are cryptographically anchored.
            </p>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 2. EMAIL FORENSICS */}
      {activeTab === 'FORENSICS' && (
        <div className="space-y-4">
          <div className="p-4 bg-soc-900 border border-soc-800 rounded space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-soc-800 pb-2">
              <span className="text-soc-300 font-bold">RFC 5322 Email Forensic Extraction</span>
              <Link
                to="/analysis/email"
                className="text-blue-400 hover:text-blue-300 text-[11px] flex items-center gap-1"
              >
                <span>Open Full Email Analyzer</span>
                <ExternalLink className="w-3 h-3" />
              </Link>
            </div>
            <div className="space-y-2">
              <div>
                <span className="text-soc-500">From: </span>
                <span className="text-soc-200">{investigation.sender}</span>
              </div>
              <div>
                <span className="text-soc-500">Subject: </span>
                <span className="text-soc-200">{investigation.subject}</span>
              </div>
              <div>
                <span className="text-soc-500">Evidence ID: </span>
                <span className="text-blue-400">{investigation.evidence_id || 'EVD-2026-00001'}</span>
              </div>
              <div>
                <span className="text-soc-500">Raw SHA-256 Digest: </span>
                <span className="text-soc-300 select-all">{investigation.evidence_hash}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 3. THREAT ASSESSMENT */}
      {activeTab === 'THREAT' && (
        <div className="space-y-4 font-mono text-xs">
          <Card title="Observable Threat Indicators">
            <div className="space-y-2">
              {overview?.top_indicators.map((ind, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-soc-200">{ind.name}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-soc-500">Weight: +{ind.score_impact}</span>
                      <Badge variant="severity" severity={ind.severity as ThreatSeverity}>
                        {ind.severity}
                      </Badge>
                    </div>
                  </div>
                  <p className="text-soc-400 text-[11px]">{ind.description}</p>
                  <div className="p-1.5 bg-soc-900 rounded text-soc-300 text-[10px] select-all">
                    Evidence: {ind.evidence_excerpt}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* TAB CONTENT: 4. AUTOMATED FORENSIC DECISION ENGINE */}
      {activeTab === 'AI_ANALYST' && (
        <div className="space-y-6 font-mono text-xs">
          {/* Header Action Banner */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 bg-soc-900 border border-soc-800 rounded">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded bg-blue-950/80 border border-blue-800/80 text-blue-400">
                <Cpu className="w-6 h-6" />
              </div>
              <div>
                <h2 className="text-sm font-bold text-soc-100 uppercase tracking-wide flex items-center gap-2">
                  <span>Automated Forensic Decision Engine</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-blue-950 border border-blue-800 text-blue-300 font-bold">
                    v{aiAssessment?.engine_version || '4.0'}
                  </span>
                </h2>
                <p className="text-[11px] text-soc-400 mt-0.5">
                  Deterministic, explainable evidence evaluation • Confidence rating • Contradiction detection • MITRE mapping.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={aiLoading}
                onClick={handleRefreshAI}
                className="px-3.5 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 text-xs"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${aiLoading ? 'animate-spin' : ''}`} />
                <span>{aiLoading ? 'Evaluating...' : 'Recalculate Assessment'}</span>
              </button>
            </div>
          </div>

          {aiAssessment ? (
            <>
              {/* Top Decision KPI Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
                <Card className="bg-soc-950 border-soc-800 p-3">
                  <span className="text-[10px] text-soc-500 uppercase block font-bold">Verdict</span>
                  <div className="text-sm font-bold mt-1">
                    {aiAssessment.verdict === 'MALICIOUS' ? (
                      <span className="text-threat-critical">MALICIOUS</span>
                    ) : aiAssessment.verdict === 'HIGH_RISK' ? (
                      <span className="text-orange-400">HIGH RISK</span>
                    ) : aiAssessment.verdict === 'SUSPICIOUS' ? (
                      <span className="text-yellow-400">SUSPICIOUS</span>
                    ) : aiAssessment.verdict === 'LOW_RISK' ? (
                      <span className="text-blue-400">LOW RISK</span>
                    ) : aiAssessment.verdict === 'BENIGN' ? (
                      <span className="text-emerald-400">BENIGN</span>
                    ) : (
                      <span className="text-soc-300">{aiAssessment.verdict || 'SUSPICIOUS'}</span>
                    )}
                  </div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Deterministic evaluation</div>
                </Card>

                <Card className="bg-soc-950 border-soc-800 p-3">
                  <span className="text-[10px] text-soc-500 uppercase block font-bold">Confidence</span>
                  <div className="text-sm font-bold text-cyan-400 mt-1">
                    {aiAssessment.confidence || 'HIGH'}
                  </div>
                  <div className="text-[10px] text-soc-500 mt-0.5">{aiAssessment.ai_confidence_percentage}% certainty</div>
                </Card>

                <Card className="bg-soc-950 border-soc-800 p-3">
                  <span className="text-[10px] text-soc-500 uppercase block font-bold">Severity</span>
                  <div className="text-sm font-bold text-amber-400 mt-1">
                    {aiAssessment.severity || investigation.severity}
                  </div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Standard taxonomy</div>
                </Card>

                <Card className="bg-soc-950 border-soc-800 p-3">
                  <span className="text-[10px] text-soc-500 uppercase block font-bold">Risk Score</span>
                  <div className="text-sm font-bold text-threat-critical mt-1">
                    {aiAssessment.risk_score ?? investigation.risk_score} / 100
                  </div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Explainable matrix</div>
                </Card>

                <Card className="bg-soc-950 border-soc-800 p-3">
                  <span className="text-[10px] text-soc-500 uppercase block font-bold">Threat Pattern</span>
                  <div className="text-xs font-bold text-yellow-300 mt-1 truncate" title={aiAssessment.threat_pattern.title}>
                    {aiAssessment.threat_pattern.title}
                  </div>
                  <div className="text-[10px] text-soc-500 mt-0.5 truncate">{aiAssessment.threat_pattern.pattern_type}</div>
                </Card>

                <Card className="bg-soc-950 border-soc-800 p-3">
                  <span className="text-[10px] text-soc-500 uppercase block font-bold">Engine</span>
                  <div className="text-xs font-bold text-blue-400 mt-1">
                    v{aiAssessment.engine_version || '4.0'}
                  </div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Rule-bounded</div>
                </Card>
              </div>

              {/* Executive Summary */}
              <Card title="Automated Executive Summary" subtitle="Synthesized high-level overview generated from observable evidence">
                <p className="text-xs text-soc-200 leading-relaxed bg-soc-950 p-3.5 rounded border border-soc-800">
                  {aiAssessment.executive_summary}
                </p>
              </Card>

              {/* Contradictions Banner if any */}
              {aiAssessment.contradictions && aiAssessment.contradictions.length > 0 && (
                <div className="p-4 rounded bg-amber-950/40 border border-amber-800/80 space-y-3">
                  <div className="flex items-center gap-2 text-amber-400 font-bold">
                    <AlertTriangle className="w-4 h-4" />
                    <span>DETECTED EVIDENCE CONTRADICTIONS ({aiAssessment.contradictions.length})</span>
                  </div>
                  <div className="space-y-2">
                    {aiAssessment.contradictions.map((contra, cIdx) => (
                      <div key={cIdx} className="p-3 rounded bg-soc-950/80 border border-amber-900/60 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-amber-300">{contra.title}</span>
                          <span className="px-1.5 py-0.5 text-[10px] rounded bg-amber-950 text-amber-400 border border-amber-800">
                            {contra.severity}
                          </span>
                        </div>
                        <p className="text-soc-300 text-xs">{contra.description}</p>
                        <div className="text-[11px] text-soc-400 flex items-center gap-1 flex-wrap">
                          <span className="text-soc-500">Conflicting elements:</span>
                          {contra.conflicting_elements.map((el, elIdx) => (
                            <span key={elIdx} className="px-1.5 py-0.5 bg-soc-900 rounded border border-soc-800 text-soc-200">
                              {el}
                            </span>
                          ))}
                        </div>
                        <div className="text-[10px] text-amber-400/90 pt-0.5">
                          <span className="font-bold">Analyst Impact:</span> {contra.impact_on_assessment}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Why This Verdict? Primary Evidence Cards */}
              {aiAssessment.primary_indicators && aiAssessment.primary_indicators.length > 0 && (
                <Card
                  title="Why this verdict? (Primary High-Impact Evidence)"
                  subtitle="Critical indicators driving the deterministic threat score and verdict"
                >
                  <div className="space-y-3">
                    {aiAssessment.primary_indicators.map((ind, idx) => (
                      <div key={idx} className="p-3.5 bg-soc-950 border border-soc-800 rounded flex flex-col md:flex-row md:items-start justify-between gap-3">
                        <div className="space-y-1.5 flex-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-950 border border-blue-800 text-blue-400 uppercase">
                              {ind.category}
                            </span>
                            <span className="font-bold text-soc-100">{ind.name}</span>
                            <Badge variant="severity" severity={ind.severity as ThreatSeverity} size="sm">
                              {ind.severity}
                            </Badge>
                            <span className="text-[10px] text-soc-500">Source: {ind.source}</span>
                          </div>
                          <p className="text-xs text-soc-300">{ind.description}</p>
                          <div className="text-[11px] text-soc-400 bg-soc-900/90 p-2 rounded border border-soc-800/80 font-mono">
                            <span className="text-soc-500 block text-[10px] uppercase font-bold">Observable Evidence:</span>
                            <span className="text-soc-200 select-all">{ind.evidence}</span>
                          </div>
                          <div className="text-[10px] text-soc-400">
                            <span className="text-soc-500 font-bold">Reason:</span> {ind.reason}
                          </div>
                        </div>
                        <div className="text-right flex-shrink-0">
                          <span className="px-2.5 py-1 rounded bg-amber-950/80 border border-amber-800 text-amber-300 font-bold text-xs">
                            +{ind.weight} pts
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Category Breakdown */}
              {aiAssessment.category_breakdowns && aiAssessment.category_breakdowns.length > 0 && (
                <Card title="Evidence Category Weight Contributions" subtitle="Breakdown of point contributions respecting category safeguards and caps">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {aiAssessment.category_breakdowns.map((cat, idx) => (
                      <div key={idx} className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] font-bold text-blue-400 uppercase">{cat.category}</span>
                          <span className="text-[10px] text-soc-500">{cat.indicators_count} hits</span>
                        </div>
                        <div className="text-base font-bold text-soc-100">
                          +{cat.capped_weight.toFixed(1)} <span className="text-[10px] text-soc-500 font-normal">pts</span>
                        </div>
                        <div className="text-[10px] text-soc-400 truncate" title={cat.summary}>
                          {cat.summary}
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Multi-Entity Correlated Findings */}
              {aiAssessment.correlated_findings && aiAssessment.correlated_findings.length > 0 && (
                <Card title="Multi-Entity Threat Correlation" subtitle="Deterministic relationships between sender, domain, routing, auth, and payloads">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {aiAssessment.correlated_findings.map((finding, idx) => (
                      <div key={idx} className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-blue-400 font-bold text-[11px]">{finding.relationship}</span>
                          <span className="text-emerald-400 text-[10px]">Conf: {Math.round(finding.confidence * 100)}%</span>
                        </div>
                        <div className="text-[11px] text-soc-300">
                          <span className="text-soc-500">{finding.source_entity}</span> ➔ <span className="text-soc-200 font-semibold">{finding.target_entity}</span>
                        </div>
                        <p className="text-soc-400 text-[11px]">{finding.evidence_details}</p>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* MITRE ATT&CK Technique Mapping */}
              {aiAssessment.mitre_techniques && aiAssessment.mitre_techniques.length > 0 && (
                <Card title="MITRE ATT&CK Technique Mapping" subtitle="Confirmed tactics and techniques grounded strictly in observable telemetry">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-soc-800 text-[11px] text-soc-400 uppercase bg-soc-950">
                          <th className="px-3 py-2">Technique ID</th>
                          <th className="px-3 py-2">Name</th>
                          <th className="px-3 py-2">Tactic</th>
                          <th className="px-3 py-2">Rationale & Evidence</th>
                          <th className="px-3 py-2 text-right">Confidence</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-soc-800/60 text-xs">
                        {aiAssessment.mitre_techniques.map((tech) => (
                          <tr key={tech.technique_id} className="hover:bg-soc-950/40">
                            <td className="px-3 py-2.5 font-bold text-blue-400 whitespace-nowrap">
                              {tech.technique_id}
                            </td>
                            <td className="px-3 py-2.5 font-semibold text-soc-200">
                              {tech.name}
                            </td>
                            <td className="px-3 py-2.5 text-soc-400">
                              {tech.tactic}
                            </td>
                            <td className="px-3 py-2.5 text-soc-300 max-w-md">
                              <div>{tech.rationale}</div>
                              <div className="text-[10px] text-soc-500 font-mono mt-0.5">{tech.evidence}</div>
                            </td>
                            <td className="px-3 py-2.5 text-right whitespace-nowrap">
                              <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800 text-[10px] font-bold">
                                {tech.confidence}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              )}

              {/* Observed Attack Progression Chain */}
              {aiAssessment.attack_narrative && aiAssessment.attack_narrative.length > 0 && (
                <Card title="Observed Attack Progression Narrative" subtitle="Chronological step-by-step reconstruction based purely on observable evidence">
                  <div className="space-y-3">
                    {aiAssessment.attack_narrative.map((step) => (
                      <div key={step.step_number} className="p-3 bg-soc-950 border border-soc-800 rounded flex items-start gap-3">
                        <div className="w-6 h-6 rounded bg-blue-950 border border-blue-800 flex items-center justify-center text-blue-400 font-bold text-xs flex-shrink-0">
                          {step.step_number}
                        </div>
                        <div className="space-y-1 flex-1">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-soc-100">{step.title}</span>
                            <span className="text-[10px] text-soc-500 uppercase">{step.phase}</span>
                          </div>
                          <p className="text-soc-300 text-xs leading-relaxed">{step.description}</p>
                          {step.evidence_excerpt && (
                            <div className="text-[10px] text-soc-400 font-mono bg-soc-900/80 p-1.5 rounded select-all">
                              Evidence: {step.evidence_excerpt}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Investigation Gap Analysis */}
              {aiAssessment.investigation_gaps && aiAssessment.investigation_gaps.length > 0 && (
                <Card title="Investigation Gap Analysis" subtitle="Telemetry not observed, unavailable externally, or unindexed">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {aiAssessment.investigation_gaps.map((gap, gIdx) => (
                      <div key={gIdx} className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-soc-200">{gap.indicator_type}</span>
                          <span className={`px-1.5 py-0.5 text-[10px] rounded font-bold border ${
                            gap.status === 'PROVIDER_UNAVAILABLE'
                              ? 'bg-amber-950/80 text-amber-400 border-amber-800'
                              : gap.status === 'NOT_AVAILABLE'
                              ? 'bg-soc-900 text-soc-400 border-soc-700'
                              : gap.status === 'NOT_CHECKED'
                              ? 'bg-blue-950/80 text-blue-400 border-blue-800'
                              : 'bg-soc-900 text-soc-500 border-soc-800'
                          }`}>
                            {gap.status}
                          </span>
                        </div>
                        <p className="text-soc-400 text-xs">{gap.description}</p>
                        <div className="text-[10px] text-soc-500">
                          <span className="font-semibold text-soc-400">Impact:</span> {gap.impact}
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Analyst Next Actions & Inquiry Questions */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Actions */}
                <Card title="Recommended Mitigation Actions" subtitle="Actionable controls categorized by operational priority">
                  <div className="space-y-2.5">
                    {aiAssessment.recommended_actions.map((act, idx) => (
                      <div key={idx} className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-blue-300">{act.title}</span>
                          <span className="px-2 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800 text-[10px] font-bold">
                            {act.action_type}
                          </span>
                        </div>
                        <p className="text-soc-300 text-xs">{act.description}</p>
                        <div className="text-[10px] text-soc-500 font-mono">Target: {act.target_indicator}</div>
                      </div>
                    ))}
                  </div>
                </Card>

                {/* Analyst Questions */}
                <Card title="Analyst Forensic Inquiry Questions" subtitle="Targeted questions for SIH triage and SOC response escalation">
                  <div className="space-y-2.5">
                    {aiAssessment.analyst_questions && aiAssessment.analyst_questions.length > 0 ? (
                      aiAssessment.analyst_questions.map((q, qIdx) => (
                        <div key={qIdx} className="p-3 bg-soc-950 border border-soc-800 rounded flex items-start gap-2.5">
                          <span className="text-blue-400 font-bold text-xs">{qIdx + 1}.</span>
                          <p className="text-soc-200 text-xs leading-relaxed">{q}</p>
                        </div>
                      ))
                    ) : (
                      <div className="text-soc-500 text-xs p-3 bg-soc-950 rounded">
                        No specific forensic escalation questions identified.
                      </div>
                    )}
                  </div>
                </Card>
              </div>
            </>
          ) : (
            <div className="p-12 text-center text-xs text-soc-500 bg-soc-900 border border-soc-800 rounded">
              <span>No decision engine assessment loaded. Click 'Recalculate Assessment' to generate.</span>
            </div>
          )}
        </div>
      )}

      {/* TAB CONTENT: 5. INTELLIGENCE & GEOIP & MULTI-ENTITY CORRELATION */}
      {activeTab === 'INTELLIGENCE' && (
        <div className="space-y-4 font-mono text-xs">
          {/* Top Banner */}
          <Card title="Threat Intelligence & Multi-Entity Correlation">
            <div className="p-4 bg-soc-950 border border-soc-800 rounded space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <span className="text-soc-200 font-semibold text-sm">Cross-Entity Correlation Engine</span>
                  <p className="text-soc-400 text-[11px] mt-0.5">
                    Deterministic cross-indicator resolution linking sender identities, reply-to routing, domains, IP hosts, and URLs.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Link
                    to="/intelligence"
                    className="px-2.5 py-1 bg-soc-800 hover:bg-soc-700 text-soc-200 rounded border border-soc-700 text-xs flex items-center gap-1.5"
                  >
                    <span>Intel Console</span>
                    <ExternalLink className="w-3 h-3" />
                  </Link>
                  <Link
                    to="/intelligence/map"
                    className="px-2.5 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs flex items-center gap-1.5 font-semibold"
                  >
                    <span>Threat Map</span>
                    <ExternalLink className="w-3 h-3" />
                  </Link>
                </div>
              </div>
            </div>
          </Card>

          {/* Correlation Metrics & Threat Signals */}
          {correlation && (
            <>
              {/* Correlation Summary Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                <div className="p-3 bg-soc-900 border border-soc-800 rounded">
                  <div className="text-[10px] text-soc-500 uppercase">Emails</div>
                  <div className="text-base font-bold text-soc-100">{correlation.emails?.length || 0}</div>
                </div>
                <div className="p-3 bg-soc-900 border border-soc-800 rounded">
                  <div className="text-[10px] text-soc-500 uppercase">Domains</div>
                  <div className="text-base font-bold text-amber-400">{correlation.domains?.length || 0}</div>
                </div>
                <div className="p-3 bg-soc-900 border border-soc-800 rounded">
                  <div className="text-[10px] text-soc-500 uppercase">URLs</div>
                  <div className="text-base font-bold text-purple-400">{correlation.urls?.length || 0}</div>
                </div>
                <div className="p-3 bg-soc-900 border border-soc-800 rounded">
                  <div className="text-[10px] text-soc-500 uppercase">IPs</div>
                  <div className="text-base font-bold text-sky-400">{correlation.ips?.length || 0}</div>
                </div>
                <div className="p-3 bg-soc-900 border border-soc-800 rounded">
                  <div className="text-[10px] text-soc-500 uppercase">Signals</div>
                  <div className={`text-base font-bold ${correlation.summary?.total_signals > 0 ? 'text-threat-critical' : 'text-emerald-400'}`}>
                    {correlation.summary?.total_signals || 0}
                  </div>
                </div>
              </div>

              {/* Correlation Threat Signals */}
              {correlation.signals && correlation.signals.length > 0 && (
                <Card title="Correlated Threat Signals (Phase 3 Engine)" subtitle="Cross-indicator risk signals contributing to threat score">
                  <div className="space-y-2.5">
                    {correlation.signals.map((sig, idx) => (
                      <div key={idx} className="p-3 bg-soc-950 border border-red-900/60 rounded flex items-start justify-between gap-3">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <ShieldAlert className="w-4 h-4 text-threat-critical flex-shrink-0" />
                            <span className="font-bold text-threat-critical">{sig.title}</span>
                            <Badge variant="severity" severity={sig.severity as ThreatSeverity} size="sm">
                              {sig.severity}
                            </Badge>
                          </div>
                          <p className="text-soc-300 text-xs">{sig.description}</p>
                          {sig.entities_involved && sig.entities_involved.length > 0 && (
                            <div className="text-[11px] text-soc-400 flex items-center gap-1.5 flex-wrap pt-0.5">
                              <span className="text-soc-500">Entities:</span>
                              {sig.entities_involved.map((ent, eIdx) => (
                                <span key={eIdx} className="px-1.5 py-0.5 bg-soc-900 rounded border border-soc-800 text-soc-300 font-mono">
                                  {ent}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                        <div className="text-right flex-shrink-0">
                          <span className="text-[10px] font-mono text-amber-400 bg-amber-950/70 border border-amber-800/80 px-2 py-0.5 rounded">
                            +{sig.weight} pts
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Correlation Evidence Graph / Relationships */}
              {correlation.relationships && correlation.relationships.length > 0 && (
                <Card title="Evidence Relationships Graph" subtitle="Linked nodes across extracted email artifacts">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    {correlation.relationships.map((rel, idx) => (
                      <div key={idx} className="p-3 bg-soc-950 border border-soc-800 rounded flex items-center justify-between">
                        <div className="space-y-0.5 truncate pr-2">
                          <div className="text-[10px] text-soc-500 uppercase font-mono">{rel.relationship}</div>
                          <div className="flex items-center gap-1.5 text-xs">
                            <span className="text-soc-200 font-semibold truncate max-w-[150px]" title={rel.source}>
                              {rel.source}
                            </span>
                            <span className="text-soc-500">➔</span>
                            <span className="text-blue-400 font-semibold truncate max-w-[150px]" title={rel.target}>
                              {rel.target}
                            </span>
                          </div>
                          {rel.evidence && <div className="text-[10px] text-soc-400 truncate">{rel.evidence}</div>}
                        </div>
                        <span className="text-[10px] text-emerald-400 font-mono px-1.5 py-0.5 bg-emerald-950/60 border border-emerald-800 rounded">
                          {Math.round(rel.confidence * 100)}%
                        </span>
                      </div>
                    ))}
                  </div>
                </Card>
              )}
            </>
          )}
        </div>
      )}

      {/* TAB CONTENT: 6. TIMELINE */}
      {activeTab === 'TIMELINE' && (
        <div className="space-y-4 font-mono text-xs">
          <Card
            title="Forensic Timeline"
            action={
              <Link
                to="/forensics/timeline"
                className="text-blue-400 hover:text-blue-300 text-[11px] flex items-center gap-1"
              >
                <span>Full Timeline Viewer</span>
                <ExternalLink className="w-3 h-3" />
              </Link>
            }
          >
            <div className="p-4 bg-soc-950 border border-soc-800 rounded text-soc-400 text-center">
              <span>Timeline events synchronized with investigation ID {investigation.id}.</span>
            </div>
          </Card>
        </div>
      )}

      {/* TAB CONTENT: 7. ATTACK GRAPH */}
      {activeTab === 'GRAPH' && (
        <div className="space-y-4 font-mono text-xs">
          <Card
            title="Interactive Attack & Evidence Graph"
            action={
              <Link
                to="/forensics/attack-graph"
                className="text-blue-400 hover:text-blue-300 text-[11px] flex items-center gap-1"
              >
                <span>Full Screen Attack Graph</span>
                <ExternalLink className="w-3 h-3" />
              </Link>
            }
          >
            <div className="p-4 bg-soc-950 border border-soc-800 rounded text-soc-400 text-center">
              <span>Attack graph relationship nodes generated for {investigation.id}.</span>
            </div>
          </Card>
        </div>
      )}

      {/* TAB CONTENT: 8. BLOCKCHAIN INTEGRITY */}
      {activeTab === 'BLOCKCHAIN' && (
        <div className="space-y-6 font-mono text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Blockchain Stored Anchor */}
            <Card title="Blockchain Ledger Anchor Record">
              <div className="space-y-2.5">
                <div className="flex justify-between py-1 border-b border-soc-800">
                  <span className="text-soc-500">Status</span>
                  <span className="text-emerald-400 font-bold">{investigation.blockchain_status}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-800">
                  <span className="text-soc-500">Network</span>
                  <span className="text-soc-200">{investigation.blockchain_network}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-soc-800">
                  <span className="text-soc-500">Block Number</span>
                  <span className="text-blue-400">#{investigation.blockchain_block || 1042}</span>
                </div>
                <div className="py-1 border-b border-soc-800">
                  <span className="text-soc-500 block mb-1">Transaction Hash</span>
                  <span className="text-soc-300 select-all truncate block text-[11px]">
                    {investigation.blockchain_tx || '0x83f9a2b1c4e720d58f310492e8ca55172b9a4c3f81e095da124376fb40192e47'}
                  </span>
                </div>
              </div>
            </Card>

            {/* Verification Testbed */}
            <Card title="Tamper Detection & Verification Testbed">
              <div className="space-y-3">
                <p className="text-soc-400 text-[11px]">
                  Perform live cryptographic verification or simulate unauthorized modification on canonical storage.
                </p>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={handleVerifyBlockchain}
                    disabled={isVerifying}
                    className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-semibold flex items-center gap-1.5 transition-colors"
                  >
                    <FileCheck className="w-3.5 h-3.5" />
                    <span>{isVerifying ? 'Verifying...' : 'Verify Integrity'}</span>
                  </button>

                  <button
                    onClick={handleSimulateTamper}
                    disabled={isTampering}
                    className="px-3 py-1.5 rounded bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 flex items-center gap-1.5 transition-colors"
                  >
                    <FileWarning className="w-3.5 h-3.5 text-red-400" />
                    <span>Simulate Tamper</span>
                  </button>

                  <button
                    onClick={handleResetTamper}
                    disabled={isTampering}
                    className="px-3 py-1.5 rounded bg-soc-800 hover:bg-soc-700 text-soc-200 border border-soc-700 flex items-center gap-1.5 transition-colors"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Reset</span>
                  </button>
                </div>

                {verificationResult && (
                  <div
                    className={`p-3 rounded border mt-3 ${
                      verificationResult.match
                        ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                        : 'bg-red-950/60 border-red-800 text-red-300'
                    }`}
                  >
                    <div className="font-bold flex items-center gap-2">
                      {verificationResult.match ? (
                        <FileCheck className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <FileWarning className="w-4 h-4 text-red-400" />
                      )}
                      <span>RESULT: {verificationResult.status}</span>
                    </div>
                    <p className="text-[11px] mt-1">{verificationResult.message}</p>
                  </div>
                )}
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 10. VERDICT & REPORT */}
      {activeTab === 'REPORT' && (
        <div className="space-y-6 font-mono text-xs">
          {/* Header Action Bar */}
          <div className="p-3 bg-soc-900 border border-soc-800 rounded flex items-center justify-between">
            <div>
              <span className="text-soc-200 font-bold">FORENSIC INVESTIGATION DOSSIER</span>
              <span className="text-soc-500 text-[11px] block">Case ID: {investigation.id} · Generated: {new Date().toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => window.print()}
                className="px-3 py-1.5 rounded bg-soc-800 hover:bg-soc-700 text-soc-200 border border-soc-700 flex items-center gap-1.5 transition-colors"
              >
                <Printer className="w-3.5 h-3.5 text-blue-400" />
                <span>Print Dossier</span>
              </button>
              <Link
                to="/reports"
                className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Full Reports Console</span>
              </Link>
            </div>
          </div>

          {/* Report Summary Card */}
          <div className="p-5 bg-soc-900 border border-soc-800 rounded space-y-4">
            <div className="border-b border-soc-800 pb-3 flex items-center justify-between">
              <div>
                <span className="text-[11px] text-soc-500 uppercase block font-semibold">Incident Classification</span>
                <span className="text-base font-bold text-soc-100">{investigation.title}</span>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="severity" severity={investigation.severity}>
                  {investigation.severity}
                </Badge>
                <span className="px-2 py-0.5 rounded bg-soc-950 text-blue-400 border border-soc-800 font-bold">
                  Score: {investigation.risk_score} / 100
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1">
                <span className="text-[10px] text-soc-500 uppercase block">Suspect Sender</span>
                <span className="text-soc-200 font-semibold select-all truncate block">{investigation.sender}</span>
              </div>
              <div className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1">
                <span className="text-[10px] text-soc-500 uppercase block">Recommended Disposition</span>
                <span className="text-threat-critical font-bold truncate block">
                  {investigation.risk_score >= 80 ? 'CONTAIN + SINKHOLE' : investigation.risk_score >= 50 ? 'INVESTIGATE + MONITOR' : 'CLOSE / BENIGN'}
                </span>
              </div>
              <div className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1">
                <span className="text-[10px] text-soc-500 uppercase block">Evidence Integrity</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <FileCheck className="w-3.5 h-3.5" />
                  <span>{investigation.blockchain_verified ? 'ANCHORED & VERIFIED' : 'PENDING'}</span>
                </span>
              </div>
            </div>

            <div className="space-y-1.5">
              <span className="text-soc-400 font-semibold uppercase text-[11px] block">Executive Threat Narrative:</span>
              <p className="p-3 bg-soc-950 border border-soc-800 rounded text-soc-300 leading-relaxed">
                {investigation.verdict_summary || investigation.description}
              </p>
            </div>

            {/* MITRE ATT&CK Snapshot */}
            {aiAssessment && aiAssessment.mitre_techniques.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-soc-400 font-semibold uppercase text-[11px] block">Correlated MITRE ATT&CK Techniques:</span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {aiAssessment.mitre_techniques.map((tech) => (
                    <div key={tech.technique_id} className="p-2.5 bg-soc-950 border border-soc-800 rounded flex items-center justify-between">
                      <div>
                        <span className="text-purple-300 font-bold">{tech.technique_id}</span>
                        <span className="text-soc-300 text-[11px] block">{tech.name}</span>
                      </div>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-soc-900 text-soc-400 border border-soc-800">
                        {tech.tactic}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB CONTENT: 11. NOTES & AUDIT TRAIL */}
      {activeTab === 'NOTES' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between pb-2 border-b border-soc-800">
            <span className="text-soc-300 font-bold">Investigation Audit Trail & Analyst Notes</span>
            <button
              onClick={() => setShowNoteModal(true)}
              className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded flex items-center gap-1"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Note</span>
            </button>
          </div>

          <div className="space-y-3">
            {investigation.notes.map((note) => (
              <div
                key={note.note_id}
                className="p-3.5 bg-soc-900 border border-soc-800 rounded space-y-1.5"
              >
                <div className="flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-blue-400">{note.author}</span>
                    <span className="px-1.5 py-0.5 rounded bg-soc-950 text-soc-400 border border-soc-800 text-[10px]">
                      {note.note_type}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-soc-500">
                      {new Date(note.timestamp).toLocaleString()}
                    </span>
                    {note.note_type !== 'SYSTEM' && (
                      <button
                        onClick={() => handleDeleteNote(note.note_id)}
                        title="Delete note"
                        className="text-soc-500 hover:text-red-400 transition-colors p-0.5"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
                <p className="text-soc-200 text-xs leading-relaxed">{note.content}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MODAL: Assign Analyst */}
      {showAssignModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 font-mono">
          <div className="w-full max-w-md bg-soc-900 border border-soc-700 rounded-md p-5 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-soc-100 flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-blue-400" />
              <span>Assign SOC Analyst</span>
            </h3>
            <div className="space-y-2">
              <label className="text-xs text-soc-400 block">Analyst Name or ID:</label>
              <input
                type="text"
                value={newAnalystName}
                onChange={(e) => setNewAnalystName(e.target.value)}
                placeholder="e.g. SOC-L2-ANALYST"
                className="w-full px-3 py-1.5 bg-soc-950 border border-soc-800 rounded text-soc-100 text-xs focus:outline-none focus:border-blue-500"
              />
            </div>
            <div className="flex justify-end gap-2 text-xs">
              <button
                onClick={() => setShowAssignModal(false)}
                className="px-3 py-1.5 bg-soc-800 text-soc-300 rounded hover:bg-soc-700"
              >
                Cancel
              </button>
              <button
                onClick={handleAssignSubmit}
                className="px-3 py-1.5 bg-blue-600 text-white rounded font-semibold hover:bg-blue-500"
              >
                Confirm Assignment
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Change Status */}
      {showStatusModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 font-mono">
          <div className="w-full max-w-md bg-soc-900 border border-soc-700 rounded-md p-5 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-soc-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-amber-400" />
              <span>Update Case Lifecycle Status</span>
            </h3>
            <div className="space-y-2">
              <label className="text-xs text-soc-400 block">Select Status:</label>
              <select
                value={newStatusValue}
                onChange={(e) => setNewStatusValue(e.target.value)}
                className="w-full px-3 py-1.5 bg-soc-950 border border-soc-800 rounded text-soc-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value="NEW">NEW</option>
                <option value="TRIAGING">TRIAGING</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="CONTAINED">CONTAINED</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="CLOSED">CLOSED</option>
                <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-xs text-soc-400 block">Transition Reason / Notes:</label>
              <textarea
                value={statusReason}
                onChange={(e) => setStatusReason(e.target.value)}
                placeholder="Reasoning for lifecycle transition..."
                rows={3}
                className="w-full px-3 py-1.5 bg-soc-950 border border-soc-800 rounded text-soc-100 text-xs focus:outline-none focus:border-blue-500"
              />
            </div>
            <div className="flex justify-end gap-2 text-xs">
              <button
                onClick={() => setShowStatusModal(false)}
                className="px-3 py-1.5 bg-soc-800 text-soc-300 rounded hover:bg-soc-700"
              >
                Cancel
              </button>
              <button
                onClick={handleStatusSubmit}
                className="px-3 py-1.5 bg-blue-600 text-white rounded font-semibold hover:bg-blue-500"
              >
                Apply Status
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Escalate Case */}
      {showEscalateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 font-mono">
          <div className="w-full max-w-md bg-soc-900 border border-soc-700 rounded-md p-5 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-red-300 flex items-center gap-2">
              <Flame className="w-4 h-4 text-red-400" />
              <span>Escalate Investigation to Incident Response</span>
            </h3>
            <div className="space-y-2">
              <label className="text-xs text-soc-400 block">Escalation Justification:</label>
              <textarea
                value={escalateReason}
                onChange={(e) => setEscalateReason(e.target.value)}
                placeholder="e.g. Critical executive impersonation requiring immediate network containment..."
                rows={3}
                className="w-full px-3 py-1.5 bg-soc-950 border border-soc-800 rounded text-soc-100 text-xs focus:outline-none focus:border-red-500"
              />
            </div>
            <div className="flex justify-end gap-2 text-xs">
              <button
                onClick={() => setShowEscalateModal(false)}
                className="px-3 py-1.5 bg-soc-800 text-soc-300 rounded hover:bg-soc-700"
              >
                Cancel
              </button>
              <button
                onClick={handleEscalateSubmit}
                className="px-3 py-1.5 bg-red-600 text-white rounded font-semibold hover:bg-red-500"
              >
                Confirm Escalation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Add Note */}
      {showNoteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 font-mono">
          <div className="w-full max-w-md bg-soc-900 border border-soc-700 rounded-md p-5 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-soc-100 flex items-center gap-2">
              <Plus className="w-4 h-4 text-emerald-400" />
              <span>Append Analyst Note to Audit Trail</span>
            </h3>
            <div className="space-y-2">
              <label className="text-xs text-soc-400 block">Note Classification:</label>
              <select
                value={noteType}
                onChange={(e) => setNoteType(e.target.value)}
                className="w-full px-3 py-1.5 bg-soc-950 border border-soc-800 rounded text-soc-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value="NOTE">NOTE (General Analysis)</option>
                <option value="ACTION">ACTION (Defensive Action Taken)</option>
                <option value="DECISION">DECISION (Analyst Verdict)</option>
                <option value="ESCALATION">ESCALATION (Tier Handoff)</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-xs text-soc-400 block">Content:</label>
              <textarea
                value={noteContent}
                onChange={(e) => setNoteContent(e.target.value)}
                placeholder="Enter investigation observations or actions..."
                rows={4}
                className="w-full px-3 py-1.5 bg-soc-950 border border-soc-800 rounded text-soc-100 text-xs focus:outline-none focus:border-blue-500"
              />
            </div>
            <div className="flex justify-end gap-2 text-xs">
              <button
                onClick={() => setShowNoteModal(false)}
                className="px-3 py-1.5 bg-soc-800 text-soc-300 rounded hover:bg-soc-700"
              >
                Cancel
              </button>
              <button
                onClick={handleAddNoteSubmit}
                className="px-3 py-1.5 bg-blue-600 text-white rounded font-semibold hover:bg-blue-500"
              >
                Save Note
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
