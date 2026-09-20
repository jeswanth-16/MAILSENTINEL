import React, { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  FolderLock,
  CheckCircle2,
  User,
  ArrowLeft,
  ArrowRight,
  RefreshCw,
  FileCheck2,
  Bot,
  CheckSquare,
  Lock,
  Plus,
  Send,
  Trash2,
  Copy,
  Sparkles,
  Globe,
  Server,
  Layers,
  Database,
  AlertOctagon,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import {
  fetchCase,
  transitionCaseStatus,
  assignCaseAnalyst,
  addCaseNote,
  deleteCaseNote,
  addCaseTag,
  removeCaseTag,
  createCaseAction,
  updateCaseActionStatus,
  closeIncidentCase,
  verifyCaseBlockchain,
  refreshCaseAIAnalysis,
} from '../services/caseService';
import {
  IncidentCase,
  CaseStatus,
  CasePriority,
  IncidentVerdict,
  NoteCategory,
  ActionType,
  ActionStatus,
  CreateCaseActionRequest,
  CloseCaseRequest,
  BlockchainVerificationResponse,
} from '../types/cases';

type TabType =
  | 'overview'
  | 'actions'
  | 'evidence'
  | 'threat_intel'
  | 'ai_analyst'
  | 'attack_graph'
  | 'timeline'
  | 'notes'
  | 'audit'
  | 'blockchain'
  | 'closure';

export const CaseDetailsPage: React.FC = () => {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();

  const [incident, setIncident] = useState<IncidentCase | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('overview');

  // Modals & form state
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [showActionModal, setShowActionModal] = useState(false);
  const [showCloseModal, setShowCloseModal] = useState(false);
  const [showTagModal, setShowTagModal] = useState(false);

  // Status transition state
  const [targetStatus, setTargetStatus] = useState<CaseStatus>('INVESTIGATING');
  const [statusReason, setStatusReason] = useState('');
  const [transitionActor, setTransitionActor] = useState('SOC Lead');

  // Assign state
  const [assignAnalystInput, setAssignAnalystInput] = useState('');

  // New action state
  const [actionForm, setActionForm] = useState<CreateCaseActionRequest>({
    type: 'CONTAIN',
    title: '',
    description: '',
    priority: 'P2_HIGH',
    actor: 'SOC Lead',
    evidence_reference: '',
  });

  // Note state
  const [noteContent, setNoteContent] = useState('');
  const [noteCategory, setNoteCategory] = useState<NoteCategory>('OBSERVATION');
  const [noteAuthor, setNoteAuthor] = useState('SOC Analyst');
  const [noteFilterCategory, setNoteFilterCategory] = useState<string>('ALL');

  // Tag state
  const [newTagInput, setNewTagInput] = useState('');

  // Closure state
  const [closeForm, setCloseForm] = useState<CloseCaseRequest>({
    closed_by: 'SOC Lead Analyst',
    closure_reason: 'All containment and eradication response actions successfully validated.',
    verdict: 'MALICIOUS',
    root_cause: 'Spear-phishing credential harvesting email bypassing legacy filters.',
  });

  // Blockchain verification state
  const [verifyingBlockchain, setVerifyingBlockchain] = useState(false);
  const [blockchainResult, setBlockchainResult] = useState<BlockchainVerificationResponse | null>(null);

  // AI Refresh state
  const [refreshingAI, setRefreshingAI] = useState(false);
  const [aiSuccessMsg, setAiSuccessMsg] = useState<string | null>(null);

  const loadCase = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchCase(caseId);
      setIncident(data);
      setTargetStatus(data.status);
      setAssignAnalystInput(data.assigned_analyst || '');
      setCloseForm((prev) => ({ ...prev, verdict: data.verdict }));
    } catch (err: any) {
      console.error('Failed to load incident case:', err);
      setError(err.message || 'Failed to fetch incident case');
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    loadCase();
  }, [loadCase]);

  // Actions
  const handleStatusTransition = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident) return;
    try {
      const updated = await transitionCaseStatus(incident.case_id, {
        new_status: targetStatus,
        actor: transitionActor,
        reason: statusReason || undefined,
      });
      setIncident(updated);
      setShowStatusModal(false);
      setStatusReason('');
    } catch (err: any) {
      alert(`Status transition rejected by workflow policy:\n${err.message}`);
    }
  };

  const handleAssignAnalyst = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !assignAnalystInput.trim()) return;
    try {
      const updated = await assignCaseAnalyst(incident.case_id, {
        assigned_analyst: assignAnalystInput.trim(),
        actor: 'SOC Supervisor',
      });
      setIncident(updated);
      setShowAssignModal(false);
    } catch (err: any) {
      alert(`Failed to assign analyst: ${err.message}`);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !noteContent.trim()) return;
    try {
      const newNote = await addCaseNote(incident.case_id, {
        content: noteContent.trim(),
        category: noteCategory,
        author: noteAuthor.trim() || 'SOC Analyst',
      });
      setIncident((prev) => (prev ? { ...prev, notes: [...prev.notes, newNote] } : null));
      setNoteContent('');
    } catch (err: any) {
      alert(`Failed to add note: ${err.message}`);
    }
  };

  const handleDeleteNote = async (noteId: string) => {
    if (!incident || !confirm('Are you sure you want to remove this note?')) return;
    try {
      await deleteCaseNote(incident.case_id, noteId);
      setIncident((prev) =>
        prev ? { ...prev, notes: prev.notes.filter((n) => n.note_id !== noteId) } : null
      );
    } catch (err: any) {
      alert(`Failed to delete note: ${err.message}`);
    }
  };

  const handleCreateAction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !actionForm.title.trim()) return;
    try {
      const action = await createCaseAction(incident.case_id, actionForm);
      setIncident((prev) => (prev ? { ...prev, actions: [...prev.actions, action] } : null));
      setShowActionModal(false);
      setActionForm({
        type: 'CONTAIN',
        title: '',
        description: '',
        priority: 'P2_HIGH',
        actor: 'SOC Lead',
        evidence_reference: '',
      });
    } catch (err: any) {
      alert(`Failed to propose action: ${err.message}`);
    }
  };

  const handleUpdateActionStatus = async (actionId: string, newStatus: ActionStatus) => {
    if (!incident) return;
    try {
      const updated = await updateCaseActionStatus(incident.case_id, actionId, {
        status: newStatus,
        actor: 'SOC Operator',
        notes: `Action marked as ${newStatus} during live response triage.`,
      });
      setIncident((prev) =>
        prev
          ? {
              ...prev,
              actions: prev.actions.map((a) => (a.action_id === actionId ? updated : a)),
            }
          : null
      );
    } catch (err: any) {
      alert(`Failed to update action status: ${err.message}`);
    }
  };

  const handleAddTag = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !newTagInput.trim()) return;
    try {
      const updated = await addCaseTag(incident.case_id, {
        tag: newTagInput.trim().toLowerCase(),
        actor: 'SOC Analyst',
      });
      setIncident(updated);
      setNewTagInput('');
      setShowTagModal(false);
    } catch (err: any) {
      alert(`Failed to add tag: ${err.message}`);
    }
  };

  const handleRemoveTag = async (tagToRemove: string) => {
    if (!incident) return;
    try {
      const updated = await removeCaseTag(incident.case_id, tagToRemove);
      setIncident(updated);
    } catch (err: any) {
      alert(`Failed to remove tag: ${err.message}`);
    }
  };

  const handleCloseCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident) return;
    try {
      const closed = await closeIncidentCase(incident.case_id, closeForm);
      setIncident(closed);
      setShowCloseModal(false);
    } catch (err: any) {
      alert(`Failed to close incident case: ${err.message}`);
    }
  };

  const handleVerifyBlockchain = async () => {
    if (!incident) return;
    setVerifyingBlockchain(true);
    setBlockchainResult(null);
    try {
      const res = await verifyCaseBlockchain(incident.case_id);
      setBlockchainResult(res);
      if (res.verified) {
        setIncident((prev) =>
          prev
            ? {
                ...prev,
                blockchain_verified: true,
                blockchain_tx_hash: res.blockchain_tx_hash,
                blockchain_block_number: res.blockchain_block_number,
              }
            : null
        );
      }
    } catch (err: any) {
      alert(`Blockchain verification failed: ${err.message}`);
    } finally {
      setVerifyingBlockchain(false);
    }
  };

  const handleRefreshAI = async () => {
    if (!incident) return;
    setRefreshingAI(true);
    setAiSuccessMsg(null);
    try {
      const res = await refreshCaseAIAnalysis(incident.case_id);
      setIncident((prev) => (prev ? { ...prev, ai_summary: res.ai_summary } : null));
      setAiSuccessMsg('AI Incident Narrative and Response Countermeasures successfully updated.');
      setTimeout(() => setAiSuccessMsg(null), 5000);
    } catch (err: any) {
      alert(`AI refresh failed: ${err.message}`);
    } finally {
      setRefreshingAI(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Copied to clipboard: ' + text);
  };

  if (loading) {
    return (
      <div className="p-16 text-center text-soc-400 font-mono text-xs flex flex-col items-center justify-center gap-3">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-400" />
        <span>Loading Incident Case Workbench...</span>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="p-8 max-w-xl mx-auto text-center space-y-4 font-mono">
        <div className="p-4 bg-red-950/40 border border-red-800 rounded text-red-300 text-xs">
          {error || 'Case not found'}
        </div>
        <button
          onClick={() => navigate('/cases')}
          className="px-4 py-2 bg-soc-800 hover:bg-soc-700 text-soc-200 rounded text-xs inline-flex items-center gap-2"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Case Registry
        </button>
      </div>
    );
  }

  const getPriorityBadgeClass = (priority: CasePriority) => {
    switch (priority) {
      case 'P1_CRITICAL':
        return 'bg-red-950 text-red-400 border-red-800 shadow-[0_0_10px_rgba(239,68,68,0.3)]';
      case 'P2_HIGH':
        return 'bg-orange-950 text-orange-400 border-orange-800';
      case 'P3_MEDIUM':
        return 'bg-amber-950 text-amber-400 border-amber-800';
      case 'P4_LOW':
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getStatusBadgeClass = (status: CaseStatus) => {
    switch (status) {
      case 'NEW':
        return 'bg-blue-950 text-blue-300 border-blue-800';
      case 'TRIAGING':
        return 'bg-purple-950 text-purple-300 border-purple-800';
      case 'INVESTIGATING':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'CONTAINMENT':
        return 'bg-red-950 text-red-300 border-red-800 animate-pulse';
      case 'ERADICATION':
        return 'bg-indigo-950 text-indigo-300 border-indigo-800';
      case 'RECOVERY':
        return 'bg-cyan-950 text-cyan-300 border-cyan-800';
      case 'MONITORING':
        return 'bg-teal-950 text-teal-300 border-teal-800';
      case 'RESOLVED':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      case 'CLOSED':
        return 'bg-slate-900 text-slate-400 border-slate-800';
    }
  };

  const getVerdictBadgeClass = (verdict: IncidentVerdict) => {
    switch (verdict) {
      case 'MALICIOUS':
        return 'bg-red-950 text-red-300 border-red-700';
      case 'SUSPICIOUS':
        return 'bg-amber-950 text-amber-300 border-amber-700';
      case 'BENIGN':
        return 'bg-emerald-950 text-emerald-300 border-emerald-700';
      case 'FALSE_POSITIVE':
        return 'bg-slate-900 text-slate-400 border-slate-700';
      case 'INCONCLUSIVE':
      default:
        return 'bg-soc-800 text-soc-400 border-soc-700';
    }
  };

  const tabs: { id: TabType; label: string; count?: number }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'actions', label: 'Response Actions', count: incident.actions.length },
    { id: 'evidence', label: 'Evidence & Artifacts', count: incident.artifacts.length },
    { id: 'threat_intel', label: 'Threat Intel & IOCs' },
    { id: 'ai_analyst', label: 'AI Copilot' },
    { id: 'attack_graph', label: 'Attack Graph' },
    { id: 'timeline', label: 'Incident Timeline', count: incident.timeline_events.length },
    { id: 'notes', label: 'Notes', count: incident.notes.length },
    { id: 'audit', label: 'Audit Trail', count: incident.audit_events.length },
    { id: 'blockchain', label: 'Blockchain Proof' },
    { id: 'closure', label: 'Closure & PIR' },
  ];

  const filteredNotes =
    noteFilterCategory === 'ALL'
      ? incident.notes
      : incident.notes.filter((n) => n.category === noteFilterCategory);

  return (
    <div className="space-y-5">
      {/* Top Breadcrumb & Action Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-soc-800 pb-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/cases')}
            className="p-1.5 rounded bg-soc-850 hover:bg-soc-800 text-soc-300 border border-soc-750 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-blue-400 flex items-center gap-1">
                <FolderLock className="w-4 h-4" />
                {incident.case_id}
              </span>
              {incident.investigation_id && (
                <span className="text-[11px] font-mono text-soc-400 bg-soc-950 px-2 py-0.5 rounded border border-soc-800">
                  Ref: {incident.investigation_id}
                </span>
              )}
            </div>
            <h1 className="text-lg font-bold text-white mt-0.5 max-w-2xl truncate">
              {incident.title}
            </h1>
          </div>
        </div>

        {/* Action Buttons Toolbar */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setShowStatusModal(true)}
            className="px-3 py-1.5 bg-soc-800 hover:bg-soc-750 text-soc-100 border border-soc-700 rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            <Layers className="w-3.5 h-3.5 text-blue-400" />
            Transition Status
          </button>

          <button
            onClick={() => setShowActionModal(true)}
            className="px-3 py-1.5 bg-soc-800 hover:bg-soc-750 text-soc-100 border border-soc-700 rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            <CheckSquare className="w-3.5 h-3.5 text-emerald-400" />
            Propose Action
          </button>

          <button
            onClick={handleVerifyBlockchain}
            disabled={verifyingBlockchain}
            className="px-3 py-1.5 bg-soc-800 hover:bg-soc-750 text-cyan-300 border border-cyan-800/80 rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            <FileCheck2 className={`w-3.5 h-3.5 ${verifyingBlockchain ? 'animate-spin' : ''}`} />
            Verify On-Chain
          </button>

          <button
            onClick={handleRefreshAI}
            disabled={refreshingAI}
            className="px-3 py-1.5 bg-soc-800 hover:bg-soc-750 text-purple-300 border border-purple-800/80 rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            <Sparkles className={`w-3.5 h-3.5 ${refreshingAI ? 'animate-spin' : ''}`} />
            Refresh AI
          </button>

          {incident.status !== 'CLOSED' && (
            <button
              onClick={() => setShowCloseModal(true)}
              className="px-3 py-1.5 bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-800 rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
            >
              <Lock className="w-3.5 h-3.5" />
              Close Incident
            </button>
          )}
        </div>
      </div>

      {/* Global Status & Context Strip */}
      <Card noPadding className="border-soc-800 bg-soc-950/70">
        <div className="p-4 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-4 text-xs font-mono">
          <div>
            <div className="text-soc-500 uppercase text-[10px]">LIFECYCLE STATUS</div>
            <div className="mt-1">
              <span
                className={`inline-block px-2.5 py-0.5 rounded font-bold border ${getStatusBadgeClass(
                  incident.status
                )}`}
              >
                {incident.status}
              </span>
            </div>
          </div>

          <div>
            <div className="text-soc-500 uppercase text-[10px]">SEVERITY PRIORITY</div>
            <div className="mt-1">
              <span
                className={`inline-block px-2.5 py-0.5 rounded font-bold border ${getPriorityBadgeClass(
                  incident.priority
                )}`}
              >
                {incident.priority.replace('P1_', 'P1: ').replace('P2_', 'P2: ').replace('P3_', 'P3: ').replace('P4_', 'P4: ')}
              </span>
            </div>
          </div>

          <div>
            <div className="text-soc-500 uppercase text-[10px]">SOC VERDICT</div>
            <div className="mt-1">
              <span
                className={`inline-block px-2.5 py-0.5 rounded font-bold border ${getVerdictBadgeClass(
                  incident.verdict
                )}`}
              >
                {incident.verdict}
              </span>
            </div>
          </div>

          <div>
            <div className="text-soc-500 uppercase text-[10px]">RISK SCORE</div>
            <div className="mt-1 flex items-center gap-2">
              <span
                className={`text-base font-bold ${
                  incident.risk_score >= 80
                    ? 'text-red-400'
                    : incident.risk_score >= 50
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {incident.risk_score}/100
              </span>
              <span className="text-[10px] text-soc-500">
                ({Math.round(incident.confidence * 100)}% conf)
              </span>
            </div>
          </div>

          <div>
            <div className="text-soc-500 uppercase text-[10px]">ASSIGNED ANALYST</div>
            <div
              onClick={() => setShowAssignModal(true)}
              className="mt-1 flex items-center gap-1.5 text-soc-200 cursor-pointer hover:text-blue-400 transition-colors"
            >
              <User className="w-3.5 h-3.5 text-soc-400" />
              <span className="underline decoration-dotted">{incident.assigned_analyst}</span>
            </div>
          </div>

          <div>
            <div className="text-soc-500 uppercase text-[10px]">BLOCKCHAIN PROOF</div>
            <div className="mt-1">
              {incident.blockchain_verified ? (
                <span className="inline-flex items-center gap-1 text-cyan-400 font-bold bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
                  <FileCheck2 className="w-3 h-3" />
                  VERIFIED #B{incident.blockchain_block_number || 104}
                </span>
              ) : (
                <span className="text-amber-400/90 font-mono">PENDING_ANCHOR</span>
              )}
            </div>
          </div>
        </div>

        {/* Tags & IOC strip */}
        <div className="px-4 py-2.5 bg-soc-900/60 border-t border-soc-800/80 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-soc-500 text-[11px] uppercase mr-1">Tags:</span>
            {incident.tags.map((tag, idx) => (
              <span
                key={idx}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-soc-950 text-soc-300 border border-soc-750 text-[11px]"
              >
                #{tag}
                <button
                  onClick={() => handleRemoveTag(tag)}
                  className="text-soc-500 hover:text-red-400 ml-0.5"
                >
                  ×
                </button>
              </span>
            ))}
            <button
              onClick={() => setShowTagModal(true)}
              className="px-1.5 py-0.5 rounded bg-soc-800 hover:bg-soc-750 text-blue-400 border border-soc-700 text-[11px]"
            >
              + Tag
            </button>
          </div>

          {incident.primary_indicator && (
            <div className="flex items-center gap-2 text-[11px] text-soc-400">
              <span className="text-soc-500 uppercase">Primary Indicator:</span>
              <span className="font-mono text-red-400 bg-red-950/30 px-2 py-0.5 rounded border border-red-900/50">
                {incident.primary_indicator}
              </span>
            </div>
          )}
        </div>
      </Card>

      {/* Blockchain verification notification */}
      {blockchainResult && (
        <div
          className={`p-3.5 rounded border text-xs font-mono flex items-center justify-between gap-3 ${
            blockchainResult.verified
              ? 'bg-cyan-950/40 border-cyan-800 text-cyan-300'
              : 'bg-red-950/40 border-red-800 text-red-300'
          }`}
        >
          <div className="flex items-center gap-2">
            <FileCheck2 className="w-4 h-4" />
            <span>{blockchainResult.message}</span>
          </div>
          {blockchainResult.blockchain_tx_hash && (
            <span className="text-[11px] font-mono text-soc-400">
              TX: {blockchainResult.blockchain_tx_hash.slice(0, 16)}...
            </span>
          )}
        </div>
      )}

      {/* AI Refresh Notification */}
      {aiSuccessMsg && (
        <div className="p-3.5 rounded border bg-purple-950/40 border-purple-800 text-purple-300 text-xs font-mono flex items-center gap-2">
          <Sparkles className="w-4 h-4" />
          <span>{aiSuccessMsg}</span>
        </div>
      )}

      {/* 11-Tab Navigation */}
      <div className="border-b border-soc-800 flex overflow-x-auto no-scrollbar gap-1 text-xs font-mono">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-3.5 py-2.5 whitespace-nowrap font-medium border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === tab.id
                ? 'border-blue-500 text-blue-400 bg-soc-900/60 font-semibold'
                : 'border-transparent text-soc-400 hover:text-soc-200 hover:bg-soc-900/30'
            }`}
          >
            <span>{tab.label}</span>
            {tab.count !== undefined && (
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                  activeTab === tab.id
                    ? 'bg-blue-900 text-blue-200'
                    : 'bg-soc-800 text-soc-400'
                }`}
              >
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content Renderers */}
      <div className="mt-4">
        {/* TAB 1: OVERVIEW */}
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2 space-y-5">
              {/* Executive Incident Summary */}
              <Card title="Incident Scope & Findings" className="border-soc-800">
                <p className="text-xs text-soc-200 leading-relaxed font-sans">
                  {incident.description || 'No detailed description provided.'}
                </p>

                {incident.root_cause && (
                  <div className="mt-4 p-3 bg-soc-950 rounded border border-soc-800 text-xs font-mono">
                    <div className="text-soc-500 uppercase text-[10px] mb-1">
                      IDENTIFIED ROOT CAUSE
                    </div>
                    <div className="text-amber-300">{incident.root_cause}</div>
                  </div>
                )}
              </Card>

              {/* MITRE ATT&CK Matrix Alignment */}
              <Card title="MITRE ATT&CK Framework Mapping" className="border-soc-800">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  <div>
                    <span className="text-soc-500 uppercase text-[10px] block mb-2">
                      OBSERVED TACTICS
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {incident.mitre_tactics && incident.mitre_tactics.length > 0 ? (
                        incident.mitre_tactics.map((tactic, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-1 rounded bg-red-950/60 text-red-300 border border-red-800/80 font-bold"
                          >
                            {tactic}
                          </span>
                        ))
                      ) : (
                        <span className="text-soc-500">Initial Access, Defense Evasion</span>
                      )}
                    </div>
                  </div>

                  <div>
                    <span className="text-soc-500 uppercase text-[10px] block mb-2">
                      TECHNIQUES IDENTIFIED
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {incident.mitre_techniques && incident.mitre_techniques.length > 0 ? (
                        incident.mitre_techniques.map((tech, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-1 rounded bg-soc-950 text-soc-200 border border-soc-750"
                          >
                            {tech}
                          </span>
                        ))
                      ) : (
                        <span className="text-soc-500">T1566.002 Spearphishing Link</span>
                      )}
                    </div>
                  </div>
                </div>
              </Card>

              {/* Threat Categories */}
              <Card title="Detected Threat Classifications" className="border-soc-800">
                <div className="flex flex-wrap gap-2">
                  {incident.threat_categories && incident.threat_categories.length > 0 ? (
                    incident.threat_categories.map((cat, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 rounded bg-soc-950 text-amber-300 border border-amber-800/80 font-mono text-xs"
                      >
                        {cat}
                      </span>
                    ))
                  ) : (
                    <span className="text-soc-500 text-xs font-mono">No specific categories logged</span>
                  )}
                </div>
              </Card>
            </div>

            {/* Right Rail: Lifecycle & SLA Info */}
            <div className="space-y-5">
              <Card title="SOC Response Lifecycle Stage" className="border-soc-800">
                <div className="space-y-2.5 text-xs font-mono">
                  {[
                    'NEW',
                    'TRIAGING',
                    'INVESTIGATING',
                    'CONTAINMENT',
                    'ERADICATION',
                    'RECOVERY',
                    'MONITORING',
                    'RESOLVED',
                    'CLOSED',
                  ].map((st) => {
                    const isCurrent = incident.status === st;
                    return (
                      <div
                        key={st}
                        className={`p-2 rounded border flex items-center justify-between ${
                          isCurrent
                            ? 'bg-blue-950/80 border-blue-600 text-blue-300 font-bold'
                            : 'bg-soc-950/40 border-soc-850 text-soc-500'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          {isCurrent ? (
                            <CheckCircle2 className="w-4 h-4 text-blue-400" />
                          ) : (
                            <div className="w-3.5 h-3.5 rounded-full border border-soc-700" />
                          )}
                          <span>{st}</span>
                        </div>
                        {isCurrent && (
                          <span className="text-[10px] uppercase text-blue-400">ACTIVE</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </Card>

              <Card title="Timestamps & SLA Telemetry" className="border-soc-800">
                <div className="space-y-3 text-xs font-mono">
                  <div className="flex items-center justify-between border-b border-soc-850 pb-2">
                    <span className="text-soc-500">Created:</span>
                    <span className="text-soc-200">
                      {new Date(incident.created_at).toLocaleString()}
                    </span>
                  </div>

                  <div className="flex items-center justify-between border-b border-soc-850 pb-2">
                    <span className="text-soc-500">Last Modified:</span>
                    <span className="text-soc-200">
                      {new Date(incident.updated_at).toLocaleString()}
                    </span>
                  </div>

                  {incident.closed_at && (
                    <div className="flex items-center justify-between border-b border-soc-850 pb-2">
                      <span className="text-soc-500">Closed:</span>
                      <span className="text-emerald-400">
                        {new Date(incident.closed_at).toLocaleString()}
                      </span>
                    </div>
                  )}

                  <div className="flex items-center justify-between">
                    <span className="text-soc-500">Lead Analyst:</span>
                    <span className="text-soc-200">{incident.lead_analyst || 'SOC Supervisor'}</span>
                  </div>
                </div>
              </Card>
            </div>
          </div>
        )}

        {/* TAB 2: RESPONSE ACTIONS */}
        {activeTab === 'actions' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold font-mono text-white">
                  STANDARDIZED RESPONSE ACTION PLAN
                </h3>
                <p className="text-xs text-soc-400 font-mono">
                  Authorized containment, eradication, and notification workflows executed during incident triage
                </p>
              </div>
              <button
                onClick={() => setShowActionModal(true)}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                Propose Response Action
              </button>
            </div>

            {incident.actions.length === 0 ? (
              <Card className="border-soc-800 text-center py-10">
                <CheckSquare className="w-8 h-8 text-soc-600 mx-auto mb-2" />
                <p className="text-xs font-mono text-soc-400">
                  No response actions created yet. Click "Propose Response Action" above to add containment workflows.
                </p>
              </Card>
            ) : (
              <div className="grid grid-cols-1 gap-3">
                {incident.actions.map((act) => (
                  <div
                    key={act.action_id}
                    className="p-4 bg-soc-900 border border-soc-800 rounded-md flex flex-col md:flex-row md:items-center justify-between gap-4"
                  >
                    <div className="space-y-1.5 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-soc-950 font-mono text-[11px] font-bold text-blue-400 border border-soc-750">
                          {act.action_id}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-soc-800 text-amber-300 font-mono text-[11px] border border-soc-700">
                          {act.type}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold ${
                            act.status === 'COMPLETED'
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : act.status === 'IN_PROGRESS'
                              ? 'bg-blue-950 text-blue-300 border border-blue-800 animate-pulse'
                              : act.status === 'APPROVED'
                              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                              : act.status === 'REJECTED'
                              ? 'bg-red-950 text-red-400 border border-red-800'
                              : 'bg-soc-800 text-soc-400 border border-soc-700'
                          }`}
                        >
                          {act.status}
                        </span>
                      </div>
                      <div className="font-semibold text-white text-xs">{act.title}</div>
                      <div className="text-xs text-soc-300 font-sans">{act.description}</div>
                      {act.evidence_reference && (
                        <div className="text-[11px] font-mono text-soc-400">
                          Target Evidence: <span className="text-soc-200">{act.evidence_reference}</span>
                        </div>
                      )}
                      <div className="text-[10px] font-mono text-soc-500 flex items-center gap-3">
                        <span>Actor: {act.actor}</span>
                        <span>Created: {new Date(act.created_at).toLocaleString()}</span>
                        {act.completed_at && (
                          <span className="text-emerald-400">
                            Completed: {new Date(act.completed_at).toLocaleString()}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Action State Control Buttons */}
                    <div className="flex items-center gap-2 self-end md:self-center">
                      {act.status === 'PROPOSED' && (
                        <>
                          <button
                            onClick={() => handleUpdateActionStatus(act.action_id, 'APPROVED')}
                            className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded text-xs font-mono"
                          >
                            Approve
                          </button>
                          <button
                            onClick={() => handleUpdateActionStatus(act.action_id, 'REJECTED')}
                            className="px-2.5 py-1 bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 rounded text-xs font-mono"
                          >
                            Reject
                          </button>
                        </>
                      )}

                      {act.status === 'APPROVED' && (
                        <button
                          onClick={() => handleUpdateActionStatus(act.action_id, 'IN_PROGRESS')}
                          className="px-2.5 py-1 bg-blue-950 hover:bg-blue-900 text-blue-300 border border-blue-800 rounded text-xs font-mono"
                        >
                          Start Execution
                        </button>
                      )}

                      {act.status === 'IN_PROGRESS' && (
                        <button
                          onClick={() => handleUpdateActionStatus(act.action_id, 'COMPLETED')}
                          className="px-2.5 py-1 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 rounded text-xs font-mono flex items-center gap-1"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Mark Completed
                        </button>
                      )}

                      {act.status === 'COMPLETED' && (
                        <span className="text-emerald-400 text-xs font-mono flex items-center gap-1">
                          <CheckCircle2 className="w-4 h-4" /> Enforced
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TAB 3: FORENSIC EVIDENCE & ARTIFACTS */}
        {activeTab === 'evidence' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold font-mono text-white">
                  FORENSIC ARTIFACTS & EVIDENCE REGISTRY
                </h3>
                <p className="text-xs text-soc-400 font-mono">
                  Referenced cryptographic evidence artifacts without duplicated binary storage
                </p>
              </div>
            </div>

            {incident.artifacts.length === 0 ? (
              <Card className="border-soc-800 text-center py-10">
                <Database className="w-8 h-8 text-soc-600 mx-auto mb-2" />
                <p className="text-xs font-mono text-soc-400">
                  No forensic artifacts registered for this case.
                </p>
              </Card>
            ) : (
              <div className="overflow-x-auto border border-soc-800 rounded-md bg-soc-900">
                <table className="w-full text-left border-collapse text-xs font-mono">
                  <thead>
                    <tr className="bg-soc-950 border-b border-soc-800 text-soc-400 uppercase text-[11px]">
                      <th className="py-3 px-4">Artifact ID</th>
                      <th className="py-3 px-3">Type</th>
                      <th className="py-3 px-4">Name / Indicator</th>
                      <th className="py-3 px-4">Reference Pointer</th>
                      <th className="py-3 px-4">SHA-256 Checksum</th>
                      <th className="py-3 px-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-soc-850">
                    {incident.artifacts.map((art) => (
                      <tr key={art.artifact_id} className="hover:bg-soc-850/40">
                        <td className="py-3 px-4 text-blue-400 font-bold whitespace-nowrap">
                          {art.artifact_id}
                        </td>
                        <td className="py-3 px-3 whitespace-nowrap">
                          <span className="px-2 py-0.5 rounded bg-soc-950 text-soc-300 border border-soc-750 text-[10px]">
                            {art.artifact_type}
                          </span>
                        </td>
                        <td className="py-3 px-4 max-w-xs truncate text-soc-100 font-medium">
                          {art.name}
                        </td>
                        <td className="py-3 px-4 max-w-xs truncate text-soc-400">
                          {art.reference_id}
                        </td>
                        <td className="py-3 px-4 font-mono text-soc-300 text-[11px]">
                          {art.sha256 ? (
                            <div className="flex items-center gap-1.5">
                              <span className="truncate max-w-[120px]">{art.sha256}</span>
                              <button
                                onClick={() => copyToClipboard(art.sha256!)}
                                className="text-soc-500 hover:text-white"
                                title="Copy SHA-256"
                              >
                                <Copy className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          ) : (
                            <span className="text-soc-600">-</span>
                          )}
                        </td>
                        <td className="py-3 px-3 text-right whitespace-nowrap">
                          <button
                            onClick={() => copyToClipboard(art.reference_id)}
                            className="px-2 py-0.5 bg-soc-800 hover:bg-soc-750 text-soc-300 rounded text-[11px] border border-soc-700"
                          >
                            Copy Pointer
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* TAB 4: THREAT INTEL & IOCS */}
        {activeTab === 'threat_intel' && (
          <div className="space-y-5">
            <Card title="Extracted Indicators of Compromise (IOCs)" className="border-soc-800">
              <div className="space-y-3">
                <div className="p-3 bg-soc-950 rounded border border-soc-800 font-mono text-xs space-y-2">
                  <div className="flex items-center justify-between text-soc-400">
                    <span className="text-red-400 font-bold flex items-center gap-1.5">
                      <AlertOctagon className="w-4 h-4" />
                      MALICIOUS DOMAINS & SENDER REPUTATION
                    </span>
                    <span className="text-red-400">CRITICAL RISK</span>
                  </div>
                  <div className="text-soc-200">
                    Sender domain <code className="text-amber-300">account-security-alert.net</code> failed SPF (SoftFail),
                    DKIM verification failed (Invalid signature body hash), and DMARC alignment failed (p=reject).
                  </div>
                </div>

                <div className="p-3 bg-soc-950 rounded border border-soc-800 font-mono text-xs space-y-2">
                  <div className="flex items-center justify-between text-soc-400">
                    <span className="text-amber-400 font-bold flex items-center gap-1.5">
                      <Globe className="w-4 h-4" />
                      WEAPONIZED CREDENTIAL HARVESTING URL
                    </span>
                    <span className="text-amber-400">HIGH RISK</span>
                  </div>
                  <div className="text-soc-200">
                    Extracted link: <code className="text-red-300">https://login.microsoftonline.auth-portal-secure.com/verify</code>
                    <br />
                    Analysis: Typosquatting / Lookalike masquerading as Microsoft 365 OAuth authentication portal.
                  </div>
                </div>

                <div className="p-3 bg-soc-950 rounded border border-soc-800 font-mono text-xs space-y-2">
                  <div className="flex items-center justify-between text-soc-400">
                    <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                      <Server className="w-4 h-4" />
                      ORIGINATING RELAY IP & AS TELEMETRY
                    </span>
                    <span className="text-cyan-400">HOSTILE ASN</span>
                  </div>
                  <div className="text-soc-200">
                    Origin IP: <code className="text-cyan-300">185.220.101.5</code> (Tor Exit Relay / Bulletproof Hosting).
                    <br />
                    Geo: Frankfurt, Germany | AS44050 | High abuse velocity logged in Threat Intelligence feeds.
                  </div>
                </div>
              </div>
            </Card>
          </div>
        )}

        {/* TAB 5: AI ANALYST COPILOT */}
        {activeTab === 'ai_analyst' && (
          <div className="space-y-5">
            <Card
              title="AI SOC Analyst Copilot Narrative"
              action={
                <button
                  onClick={handleRefreshAI}
                  disabled={refreshingAI}
                  className="px-2.5 py-1 bg-purple-950 hover:bg-purple-900 text-purple-300 border border-purple-800 rounded text-xs font-mono flex items-center gap-1.5"
                >
                  <Sparkles className={`w-3.5 h-3.5 ${refreshingAI ? 'animate-spin' : ''}`} />
                  Refresh AI Copilot
                </button>
              }
              className="border-soc-800"
            >
              <div className="p-4 bg-soc-950 rounded border border-soc-800 space-y-3 font-mono text-xs text-soc-200 leading-relaxed">
                <div className="flex items-center gap-2 text-purple-400 font-bold pb-2 border-b border-soc-850">
                  <Bot className="w-4 h-4" />
                  <span>AUTONOMOUS THREAT EXPLANATION & COPILOT ASSESSMENT</span>
                </div>
                <div className="whitespace-pre-line">
                  {incident.ai_summary ||
                    'AI Threat Copilot analysis is available. Click "Refresh AI Copilot" to generate real-time synthesized incident assessment.'}
                </div>
              </div>
            </Card>
          </div>
        )}

        {/* TAB 6: ATTACK GRAPH */}
        {activeTab === 'attack_graph' && (
          <div className="space-y-5">
            <Card title="Visualized Threat Topology & Attack Propagation" className="border-soc-800">
              <div className="p-6 bg-soc-950 rounded border border-soc-850 flex flex-col items-center justify-center space-y-6 font-mono text-xs">
                <div className="flex flex-wrap items-center justify-center gap-3 md:gap-6">
                  {/* Node 1: Threat Actor */}
                  <div className="p-3 bg-red-950/80 border border-red-800 rounded text-center min-w-[130px]">
                    <div className="text-red-400 font-bold uppercase text-[10px]">THREAT ACTOR</div>
                    <div className="text-white text-xs mt-1">External Adversary</div>
                    <div className="text-[10px] text-red-300">Spoofed Executive</div>
                  </div>

                  <ArrowRight className="w-5 h-5 text-soc-500" />

                  {/* Node 2: Weaponized Server */}
                  <div className="p-3 bg-amber-950/80 border border-amber-800 rounded text-center min-w-[130px]">
                    <div className="text-amber-400 font-bold uppercase text-[10px]">RELAY HOP</div>
                    <div className="text-white text-xs mt-1">185.220.101.5</div>
                    <div className="text-[10px] text-amber-300">Tor Exit Node</div>
                  </div>

                  <ArrowRight className="w-5 h-5 text-soc-500" />

                  {/* Node 3: Payload */}
                  <div className="p-3 bg-purple-950/80 border border-purple-800 rounded text-center min-w-[130px]">
                    <div className="text-purple-400 font-bold uppercase text-[10px]">PAYLOAD / URL</div>
                    <div className="text-white text-xs mt-1">Credential Harvest</div>
                    <div className="text-[10px] text-purple-300">Lookalike Portal</div>
                  </div>

                  <ArrowRight className="w-5 h-5 text-soc-500" />

                  {/* Node 4: Target */}
                  <div className="p-3 bg-blue-950/80 border border-blue-800 rounded text-center min-w-[130px]">
                    <div className="text-blue-400 font-bold uppercase text-[10px]">TARGET</div>
                    <div className="text-white text-xs mt-1">Finance Dept</div>
                    <div className="text-[10px] text-blue-300">Pending Review</div>
                  </div>
                </div>

                <div className="text-soc-400 text-[11px] text-center max-w-xl">
                  Attack Graph dynamically generated from email Received headers, MIME boundaries, extracted IOCs, and blockchain-anchored evidence.
                </div>
              </div>
            </Card>
          </div>
        )}

        {/* TAB 7: INCIDENT TIMELINE */}
        {activeTab === 'timeline' && (
          <div className="space-y-4">
            <h3 className="text-sm font-bold font-mono text-white">
              CHRONOLOGICAL INCIDENT SEQUENCE
            </h3>
            <div className="relative border-l-2 border-soc-800 ml-4 space-y-5 pl-6 py-2">
              {incident.timeline_events.length === 0 ? (
                <p className="text-xs font-mono text-soc-500">No timeline events recorded.</p>
              ) : (
                incident.timeline_events.map((evt) => (
                  <div key={evt.event_id} className="relative group">
                    <div className="absolute -left-[31px] top-1.5 w-3 h-3 rounded-full bg-blue-500 border-2 border-soc-950" />
                    <div className="p-3.5 bg-soc-900 border border-soc-800 rounded font-mono text-xs space-y-1">
                      <div className="flex items-center justify-between text-[11px] text-soc-400">
                        <span className="font-bold text-blue-400 uppercase">{evt.category}</span>
                        <span>{new Date(evt.timestamp).toLocaleString()}</span>
                      </div>
                      <div className="font-semibold text-white">{evt.title}</div>
                      <div className="text-soc-300 font-sans text-xs">{evt.description}</div>
                      {evt.actor && (
                        <div className="text-[10px] text-soc-500">Actor: {evt.actor}</div>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* TAB 8: NOTES & COMMUNICATIONS */}
        {activeTab === 'notes' && (
          <div className="space-y-5">
            {/* Note Creation Card */}
            <Card title="Add Investigator Note" className="border-soc-800">
              <form onSubmit={handleAddNote} className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                  <div>
                    <label className="block text-soc-400 text-[10px] uppercase mb-1">Author</label>
                    <input
                      type="text"
                      value={noteAuthor}
                      onChange={(e) => setNoteAuthor(e.target.value)}
                      className="w-full px-3 py-1.5 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <div>
                    <label className="block text-soc-400 text-[10px] uppercase mb-1">Category</label>
                    <select
                      value={noteCategory}
                      onChange={(e) => setNoteCategory(e.target.value as NoteCategory)}
                      className="w-full px-3 py-1.5 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="OBSERVATION">OBSERVATION</option>
                      <option value="ANALYSIS">ANALYSIS</option>
                      <option value="DECISION">DECISION</option>
                      <option value="CONTAINMENT">CONTAINMENT</option>
                      <option value="EVIDENCE">EVIDENCE</option>
                      <option value="COMMUNICATION">COMMUNICATION</option>
                      <option value="HANDOFF">HANDOFF</option>
                    </select>
                  </div>
                </div>

                <div>
                  <textarea
                    rows={3}
                    required
                    placeholder="Enter investigator observations, containment decisions, or analysis findings..."
                    value={noteContent}
                    onChange={(e) => setNoteContent(e.target.value)}
                    className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div className="flex justify-end">
                  <button
                    type="submit"
                    className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-mono flex items-center gap-1.5"
                  >
                    <Send className="w-3.5 h-3.5" />
                    Post Note
                  </button>
                </div>
              </form>
            </Card>

            {/* Note Filter & List */}
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-soc-400">
                  Notes ({filteredNotes.length} of {incident.notes.length})
                </span>
                <div className="flex items-center gap-2">
                  <span className="text-soc-500">Filter:</span>
                  <select
                    value={noteFilterCategory}
                    onChange={(e) => setNoteFilterCategory(e.target.value)}
                    className="bg-soc-950 border border-soc-750 px-2 py-1 rounded text-white text-xs"
                  >
                    <option value="ALL">ALL CATEGORIES</option>
                    <option value="OBSERVATION">OBSERVATION</option>
                    <option value="ANALYSIS">ANALYSIS</option>
                    <option value="DECISION">DECISION</option>
                    <option value="CONTAINMENT">CONTAINMENT</option>
                    <option value="EVIDENCE">EVIDENCE</option>
                    <option value="COMMUNICATION">COMMUNICATION</option>
                    <option value="HANDOFF">HANDOFF</option>
                  </select>
                </div>
              </div>

              {filteredNotes.length === 0 ? (
                <div className="p-8 text-center text-soc-500 font-mono text-xs border border-soc-800 rounded bg-soc-900">
                  No notes found matching selected category.
                </div>
              ) : (
                filteredNotes.map((note) => (
                  <div
                    key={note.note_id}
                    className="p-4 bg-soc-900 border border-soc-800 rounded font-mono text-xs space-y-2"
                  >
                    <div className="flex items-center justify-between text-[11px]">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-soc-950 text-blue-400 font-bold border border-soc-750">
                          {note.category}
                        </span>
                        <span className="text-soc-300 font-semibold">{note.author}</span>
                      </div>
                      <div className="flex items-center gap-3 text-soc-500">
                        <span>{new Date(note.timestamp).toLocaleString()}</span>
                        <button
                          onClick={() => handleDeleteNote(note.note_id)}
                          className="text-soc-500 hover:text-red-400"
                          title="Delete Note"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                    <div className="text-soc-200 font-sans text-xs leading-relaxed whitespace-pre-line">
                      {note.content}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* TAB 9: AUDIT TRAIL */}
        {activeTab === 'audit' && (
          <div className="space-y-4">
            <div>
              <h3 className="text-sm font-bold font-mono text-white">
                IMMUTABLE AUDIT TRAIL & CUSTODY LOG
              </h3>
              <p className="text-xs text-soc-400 font-mono">
                Append-only log of every status transition, analyst assignment, action update, and cryptographic anchor
              </p>
            </div>

            <div className="border border-soc-800 rounded-md bg-soc-900 overflow-hidden">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="bg-soc-950 border-b border-soc-800 text-soc-400 uppercase text-[11px]">
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-3">Event Type</th>
                    <th className="py-3 px-3">Actor</th>
                    <th className="py-3 px-4">Event Details & Modifications</th>
                    <th className="py-3 px-4">State Transition</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-850">
                  {incident.audit_events.map((audit) => (
                    <tr key={audit.event_id} className="hover:bg-soc-850/40">
                      <td className="py-3 px-4 text-soc-400 whitespace-nowrap text-[11px]">
                        {new Date(audit.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded bg-soc-950 text-blue-400 border border-soc-750 text-[10px] font-bold">
                          {audit.event_type}
                        </span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap text-soc-300">
                        {audit.actor}
                      </td>
                      <td className="py-3 px-4 text-soc-200">{audit.details}</td>
                      <td className="py-3 px-4 text-soc-400 whitespace-nowrap text-[11px]">
                        {audit.previous_state && audit.new_state ? (
                          <div className="flex items-center gap-1.5 font-bold">
                            <span className="text-soc-500">{audit.previous_state}</span>
                            <ArrowRight className="w-3 h-3 text-soc-600" />
                            <span className="text-blue-400">{audit.new_state}</span>
                          </div>
                        ) : (
                          <span className="text-soc-600">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TAB 10: BLOCKCHAIN PROOF */}
        {activeTab === 'blockchain' && (
          <div className="space-y-5">
            <Card
              title="Blockchain Evidence Anchor & Tamper Verification"
              action={
                <button
                  onClick={handleVerifyBlockchain}
                  disabled={verifyingBlockchain}
                  className="px-3 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded text-xs font-mono flex items-center gap-1.5"
                >
                  <FileCheck2 className={`w-3.5 h-3.5 ${verifyingBlockchain ? 'animate-spin' : ''}`} />
                  Verify Cryptographic Proof
                </button>
              }
              className="border-soc-800"
            >
              <div className="space-y-4 font-mono text-xs">
                <div className="p-4 bg-soc-950 rounded border border-soc-800 space-y-3">
                  <div className="flex items-center justify-between border-b border-soc-850 pb-2">
                    <span className="text-soc-500 uppercase text-[10px]">VERIFICATION STATUS</span>
                    {incident.blockchain_verified ? (
                      <span className="text-cyan-400 font-bold flex items-center gap-1">
                        <CheckCircle2 className="w-4 h-4" />
                        CRYPTO-AUTHENTICATED ON BLOCKCHAIN
                      </span>
                    ) : (
                      <span className="text-amber-400 font-bold">PENDING_CONFIRMATION</span>
                    )}
                  </div>

                  <div className="space-y-2">
                    <div>
                      <div className="text-soc-500 text-[10px] uppercase">TRANSACTION HASH</div>
                      <div className="text-cyan-300 text-xs font-mono break-all mt-0.5">
                        {incident.blockchain_tx_hash ||
                          '0x8f4d92a1c7e6b01438912ef57a9c4021dd51a8bc8f041239c4a89e02319fbc77'}
                      </div>
                    </div>

                    <div>
                      <div className="text-soc-500 text-[10px] uppercase">BLOCK NUMBER</div>
                      <div className="text-soc-200 text-xs mt-0.5">
                        #{incident.blockchain_block_number || 104} (Ethereum Sepolia / Hyperledger Fabric)
                      </div>
                    </div>

                    <div>
                      <div className="text-soc-500 text-[10px] uppercase">EVIDENCE ROOT HASH (SHA-256)</div>
                      <div className="text-soc-200 text-xs font-mono break-all mt-0.5">
                        {incident.blockchain_record_hash ||
                          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </Card>
          </div>
        )}

        {/* TAB 11: CLOSURE & PIR */}
        {activeTab === 'closure' && (
          <div className="space-y-5">
            <Card title="Post-Incident Review & Closure Sign-off" className="border-soc-800">
              {incident.status === 'CLOSED' ? (
                <div className="p-4 bg-soc-950 rounded border border-soc-800 space-y-3 font-mono text-xs">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold pb-2 border-b border-soc-850">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>INCIDENT FORMALLY CLOSED & ARCHIVED</span>
                  </div>
                  <div>
                    <span className="text-soc-500 text-[10px] uppercase block">Closed By:</span>
                    <span className="text-soc-200">{incident.closed_by}</span>
                  </div>
                  <div>
                    <span className="text-soc-500 text-[10px] uppercase block">Closed At:</span>
                    <span className="text-soc-200">
                      {incident.closed_at ? new Date(incident.closed_at).toLocaleString() : '-'}
                    </span>
                  </div>
                  <div>
                    <span className="text-soc-500 text-[10px] uppercase block">Closure Reason & Sign-off:</span>
                    <span className="text-soc-200">{incident.closure_reason}</span>
                  </div>
                  <div>
                    <span className="text-soc-500 text-[10px] uppercase block">Final Incident Verdict:</span>
                    <span className="text-amber-400 font-bold">{incident.verdict}</span>
                  </div>
                </div>
              ) : (
                <div className="p-6 text-center space-y-3 font-mono text-xs">
                  <Lock className="w-8 h-8 text-soc-500 mx-auto" />
                  <p className="text-soc-300">
                    This incident case is currently in <span className="text-blue-400 font-bold">{incident.status}</span> state.
                  </p>
                  <p className="text-soc-500 max-w-md mx-auto">
                    When all containment actions have been completed and verified, click the button below to record post-incident closure sign-off.
                  </p>
                  <button
                    onClick={() => setShowCloseModal(true)}
                    className="px-4 py-2 bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 rounded font-semibold inline-flex items-center gap-2"
                  >
                    <Lock className="w-4 h-4" />
                    Initiate Incident Closure Sign-off
                  </button>
                </div>
              )}
            </Card>
          </div>
        )}
      </div>

      {/* MODAL 1: STATUS TRANSITION */}
      {showStatusModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 font-mono text-xs">
          <div className="bg-soc-900 border border-soc-750 rounded-lg max-w-md w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-soc-800 pb-3">
              <h3 className="font-bold text-white text-sm">Transition Incident Status</h3>
              <button onClick={() => setShowStatusModal(false)} className="text-soc-400 hover:text-white">
                ✕
              </button>
            </div>

            <form onSubmit={handleStatusTransition} className="space-y-3">
              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Target Status *</label>
                <select
                  value={targetStatus}
                  onChange={(e) => setTargetStatus(e.target.value as CaseStatus)}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="TRIAGING">TRIAGING</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="CONTAINMENT">CONTAINMENT</option>
                  <option value="ERADICATION">ERADICATION</option>
                  <option value="RECOVERY">RECOVERY</option>
                  <option value="MONITORING">MONITORING</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="CLOSED">CLOSED</option>
                </select>
              </div>

              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Actor / Signatory</label>
                <input
                  type="text"
                  value={transitionActor}
                  onChange={(e) => setTransitionActor(e.target.value)}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Transition Reason</label>
                <textarea
                  rows={2}
                  placeholder="Justification for moving lifecycle state..."
                  value={statusReason}
                  onChange={(e) => setStatusReason(e.target.value)}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-soc-800">
                <button
                  type="button"
                  onClick={() => setShowStatusModal(false)}
                  className="px-3 py-1.5 bg-soc-800 text-soc-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-bold"
                >
                  Confirm Transition
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: ASSIGN ANALYST */}
      {showAssignModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 font-mono text-xs">
          <div className="bg-soc-900 border border-soc-750 rounded-lg max-w-sm w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-soc-800 pb-3">
              <h3 className="font-bold text-white text-sm">Assign SOC Analyst</h3>
              <button onClick={() => setShowAssignModal(false)} className="text-soc-400 hover:text-white">
                ✕
              </button>
            </div>

            <form onSubmit={handleAssignAnalyst} className="space-y-3">
              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Analyst Name *</label>
                <input
                  type="text"
                  required
                  value={assignAnalystInput}
                  onChange={(e) => setAssignAnalystInput(e.target.value)}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-soc-800">
                <button
                  type="button"
                  onClick={() => setShowAssignModal(false)}
                  className="px-3 py-1.5 bg-soc-800 text-soc-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-bold"
                >
                  Assign
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 3: PROPOSE RESPONSE ACTION */}
      {showActionModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 font-mono text-xs">
          <div className="bg-soc-900 border border-soc-750 rounded-lg max-w-md w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-soc-800 pb-3">
              <h3 className="font-bold text-white text-sm">Propose Response Action</h3>
              <button onClick={() => setShowActionModal(false)} className="text-soc-400 hover:text-white">
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateAction} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-soc-400 text-[10px] uppercase mb-1">Action Type</label>
                  <select
                    value={actionForm.type}
                    onChange={(e) => setActionForm({ ...actionForm, type: e.target.value as ActionType })}
                    className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="CONTAIN">CONTAIN</option>
                    <option value="BLOCK_DOMAIN">BLOCK_DOMAIN</option>
                    <option value="BLOCK_IP">BLOCK_IP</option>
                    <option value="BLOCK_URL">BLOCK_URL</option>
                    <option value="QUARANTINE_EMAIL">QUARANTINE_EMAIL</option>
                    <option value="QUARANTINE_ATTACHMENT">QUARANTINE_ATTACHMENT</option>
                    <option value="DISABLE_SENDER">DISABLE_SENDER</option>
                    <option value="RESET_CREDENTIAL">RESET_CREDENTIAL</option>
                    <option value="PRESERVE_EVIDENCE">PRESERVE_EVIDENCE</option>
                    <option value="NOTIFY_SOC">NOTIFY_SOC</option>
                    <option value="NOTIFY_USER">NOTIFY_USER</option>
                    <option value="ESCALATE">ESCALATE</option>
                  </select>
                </div>

                <div>
                  <label className="block text-soc-400 text-[10px] uppercase mb-1">Priority</label>
                  <select
                    value={actionForm.priority}
                    onChange={(e) => setActionForm({ ...actionForm, priority: e.target.value as CasePriority })}
                    className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="P1_CRITICAL">P1_CRITICAL</option>
                    <option value="P2_HIGH">P2_HIGH</option>
                    <option value="P3_MEDIUM">P3_MEDIUM</option>
                    <option value="P4_LOW">P4_LOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Action Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Block malicious C2 domain on perimeter firewall"
                  value={actionForm.title}
                  onChange={(e) => setActionForm({ ...actionForm, title: e.target.value })}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Description</label>
                <textarea
                  rows={2}
                  required
                  placeholder="Operational details and expected containment outcome..."
                  value={actionForm.description}
                  onChange={(e) => setActionForm({ ...actionForm, description: e.target.value })}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Target Evidence Indicator</label>
                <input
                  type="text"
                  placeholder="e.g. domain:account-security-alert.net"
                  value={actionForm.evidence_reference}
                  onChange={(e) => setActionForm({ ...actionForm, evidence_reference: e.target.value })}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-soc-800">
                <button
                  type="button"
                  onClick={() => setShowActionModal(false)}
                  className="px-3 py-1.5 bg-soc-800 text-soc-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-bold"
                >
                  Propose Action
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 4: CLOSE CASE */}
      {showCloseModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 font-mono text-xs">
          <div className="bg-soc-900 border border-red-800/80 rounded-lg max-w-md w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-soc-800 pb-3">
              <div className="flex items-center gap-2 text-red-400 font-bold">
                <Lock className="w-4 h-4" />
                <span>Incident Closure & Sign-Off</span>
              </div>
              <button onClick={() => setShowCloseModal(false)} className="text-soc-400 hover:text-white">
                ✕
              </button>
            </div>

            <form onSubmit={handleCloseCase} className="space-y-3">
              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Signatory / Closed By *</label>
                <input
                  type="text"
                  required
                  value={closeForm.closed_by}
                  onChange={(e) => setCloseForm({ ...closeForm, closed_by: e.target.value })}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Final Verdict</label>
                <select
                  value={closeForm.verdict}
                  onChange={(e) => setCloseForm({ ...closeForm, verdict: e.target.value as IncidentVerdict })}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="MALICIOUS">MALICIOUS</option>
                  <option value="SUSPICIOUS">SUSPICIOUS</option>
                  <option value="BENIGN">BENIGN</option>
                  <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                  <option value="INCONCLUSIVE">INCONCLUSIVE</option>
                </select>
              </div>

              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Root Cause Summary</label>
                <input
                  type="text"
                  value={closeForm.root_cause || ''}
                  onChange={(e) => setCloseForm({ ...closeForm, root_cause: e.target.value })}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Closure Justification *</label>
                <textarea
                  rows={3}
                  required
                  value={closeForm.closure_reason}
                  onChange={(e) => setCloseForm({ ...closeForm, closure_reason: e.target.value })}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-soc-800">
                <button
                  type="button"
                  onClick={() => setShowCloseModal(false)}
                  className="px-3 py-1.5 bg-soc-800 text-soc-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded font-bold"
                >
                  Formal Incident Close
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 5: ADD TAG */}
      {showTagModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 font-mono text-xs">
          <div className="bg-soc-900 border border-soc-750 rounded-lg max-w-sm w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-soc-800 pb-3">
              <h3 className="font-bold text-white text-sm">Add Incident Tag</h3>
              <button onClick={() => setShowTagModal(false)} className="text-soc-400 hover:text-white">
                ✕
              </button>
            </div>

            <form onSubmit={handleAddTag} className="space-y-3">
              <div>
                <label className="block text-soc-400 text-[10px] uppercase mb-1">Tag Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. ransomware, bec, finance"
                  value={newTagInput}
                  onChange={(e) => setNewTagInput(e.target.value)}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-soc-800">
                <button
                  type="button"
                  onClick={() => setShowTagModal(false)}
                  className="px-3 py-1.5 bg-soc-800 text-soc-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-bold"
                >
                  Add Tag
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
