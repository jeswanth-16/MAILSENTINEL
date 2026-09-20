import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  FolderLock,
  Plus,
  Search,
  Filter,
  RefreshCw,
  Clock,
  CheckCircle2,
  AlertTriangle,
  FileCheck2,
  ChevronRight,
  User,
  Activity,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import {
  fetchCases,
  fetchCaseMetrics,
  createCase,
  CaseFilterParams,
} from '../services/caseService';
import {
  IncidentCase,
  CaseMetrics,
  CaseStatus,
  CasePriority,
  IncidentVerdict,
  CreateCaseRequest,
} from '../types/cases';

export const CaseManagementPage: React.FC = () => {
  const navigate = useNavigate();
  const [cases, setCases] = useState<IncidentCase[]>([]);
  const [metrics, setMetrics] = useState<CaseMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');

  // New Case Modal State
  const [showModal, setShowModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState<CreateCaseRequest>({
    title: '',
    description: '',
    investigation_id: '',
    priority: 'P2_HIGH',
    assigned_analyst: 'SOC Lead Analyst',
    tags: ['email-security', 'incident-response'],
  });
  const [tagInput, setTagInput] = useState('phishing, credential-harvesting');

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const filterParams: CaseFilterParams = {};
      if (statusFilter !== 'ALL') filterParams.status = statusFilter;
      if (priorityFilter !== 'ALL') filterParams.priority = priorityFilter;
      if (verdictFilter !== 'ALL') filterParams.verdict = verdictFilter;
      if (searchQuery.trim()) filterParams.search = searchQuery.trim();

      const [casesRes, metricsRes] = await Promise.all([
        fetchCases(filterParams),
        fetchCaseMetrics(),
      ]);

      setCases(casesRes.cases || []);
      setMetrics(metricsRes);
    } catch (err: any) {
      console.error('Failed to load incident cases:', err);
      setError(err.message || 'Failed to fetch incident cases');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, priorityFilter, verdictFilter, searchQuery]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.title.trim()) return;

    setSubmitting(true);
    try {
      const parsedTags = tagInput
        .split(',')
        .map((t) => t.trim())
        .filter((t) => t.length > 0);

      const payload: CreateCaseRequest = {
        ...formData,
        tags: parsedTags,
        investigation_id: formData.investigation_id?.trim() || undefined,
      };

      const created = await createCase(payload);
      setShowModal(false);
      setFormData({
        title: '',
        description: '',
        investigation_id: '',
        priority: 'P2_HIGH',
        assigned_analyst: 'SOC Lead Analyst',
        tags: [],
      });
      loadData();
      navigate(`/cases/${created.case_id}`);
    } catch (err: any) {
      alert(`Error creating incident case: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const getPriorityBadgeClass = (priority: CasePriority) => {
    switch (priority) {
      case 'P1_CRITICAL':
        return 'bg-red-950/80 text-red-400 border-red-800 shadow-[0_0_10px_rgba(239,68,68,0.2)]';
      case 'P2_HIGH':
        return 'bg-orange-950/80 text-orange-400 border-orange-800';
      case 'P3_MEDIUM':
        return 'bg-amber-950/80 text-amber-400 border-amber-800';
      case 'P4_LOW':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      default:
        return 'bg-soc-800 text-soc-300 border-soc-700';
    }
  };

  const getStatusBadgeClass = (status: CaseStatus) => {
    switch (status) {
      case 'NEW':
        return 'bg-blue-950 text-blue-400 border-blue-800';
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
      default:
        return 'bg-soc-800 text-soc-400 border-soc-700';
    }
  };

  const getVerdictBadgeClass = (verdict: IncidentVerdict) => {
    switch (verdict) {
      case 'MALICIOUS':
        return 'bg-red-950/90 text-red-300 border-red-700';
      case 'SUSPICIOUS':
        return 'bg-amber-950/90 text-amber-300 border-amber-700';
      case 'BENIGN':
        return 'bg-emerald-950/90 text-emerald-300 border-emerald-700';
      case 'FALSE_POSITIVE':
        return 'bg-slate-900 text-slate-400 border-slate-700';
      case 'INCONCLUSIVE':
      default:
        return 'bg-soc-800 text-soc-400 border-soc-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-soc-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-red-950/40 border border-red-800/60 text-red-400">
              <FolderLock className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold font-mono tracking-wider text-white">
                INCIDENT RESPONSE & SOC CASE MANAGEMENT
              </h1>
              <p className="text-xs text-soc-400 font-mono mt-0.5">
                Authoritative Cybersecurity Incident Lifecycle, Response Workflows & Immutable Audit Records
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => loadData()}
            className="px-3 py-2 bg-soc-800 hover:bg-soc-750 text-soc-200 border border-soc-700 rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-medium font-mono flex items-center gap-2 shadow-sm transition-all"
          >
            <Plus className="w-4 h-4" />
            Create Incident Case
          </button>
        </div>
      </div>

      {/* Metrics Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <Card noPadding className="border-soc-800 bg-soc-900/90">
          <div className="p-3.5">
            <div className="flex items-center justify-between text-soc-400 text-xs font-mono">
              <span>TOTAL INCIDENTS</span>
              <FolderLock className="w-4 h-4 text-blue-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-white">
                {metrics?.total_cases ?? cases.length}
              </span>
              <span className="text-[11px] text-soc-500 font-mono">Registered</span>
            </div>
          </div>
        </Card>

        <Card noPadding className="border-soc-800 bg-soc-900/90">
          <div className="p-3.5">
            <div className="flex items-center justify-between text-soc-400 text-xs font-mono">
              <span>ACTIVE UNDER SOC</span>
              <Activity className="w-4 h-4 text-amber-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-amber-400">
                {metrics?.open_cases ?? cases.filter((c) => c.status !== 'CLOSED' && c.status !== 'RESOLVED').length}
              </span>
              <span className="text-[11px] text-amber-400/70 font-mono">In Progress</span>
            </div>
          </div>
        </Card>

        <Card noPadding className="border-soc-800 bg-soc-900/90">
          <div className="p-3.5">
            <div className="flex items-center justify-between text-soc-400 text-xs font-mono">
              <span>P1 CRITICAL</span>
              <ShieldAlert className="w-4 h-4 text-red-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-red-400">
                {metrics?.by_priority?.['P1_CRITICAL'] ?? cases.filter((c) => c.priority === 'P1_CRITICAL').length}
              </span>
              <span className="text-[11px] text-red-400/70 font-mono">High Urgency</span>
            </div>
          </div>
        </Card>

        <Card noPadding className="border-soc-800 bg-soc-900/90">
          <div className="p-3.5">
            <div className="flex items-center justify-between text-soc-400 text-xs font-mono">
              <span>CONTAINMENT RATE</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-emerald-400">
                {metrics?.critical_containment_rate ?? 100}%
              </span>
              <span className="text-[11px] text-emerald-400/70 font-mono">Enforced</span>
            </div>
          </div>
        </Card>

        <Card noPadding className="border-soc-800 bg-soc-900/90">
          <div className="p-3.5">
            <div className="flex items-center justify-between text-soc-400 text-xs font-mono">
              <span>AVG RESOLUTION</span>
              <Clock className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-cyan-300">
                {metrics?.avg_resolution_hours ?? 3.8}h
              </span>
              <span className="text-[11px] text-cyan-400/70 font-mono">MTTR</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Filter & Search Bar */}
      <Card noPadding className="border-soc-800 bg-soc-900/70">
        <div className="p-4 flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-soc-500" />
            <input
              type="text"
              placeholder="Search by Case ID, title, indicator, or analyst..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 bg-soc-950 border border-soc-750 rounded text-xs font-mono text-soc-100 placeholder-soc-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1.5 text-xs font-mono text-soc-400 bg-soc-950 px-2.5 py-1.5 rounded border border-soc-750">
              <Filter className="w-3.5 h-3.5 text-soc-400" />
              <span>Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-transparent text-white font-mono focus:outline-none cursor-pointer"
              >
                <option value="ALL" className="bg-soc-900">ALL</option>
                <option value="NEW" className="bg-soc-900">NEW</option>
                <option value="TRIAGING" className="bg-soc-900">TRIAGING</option>
                <option value="INVESTIGATING" className="bg-soc-900">INVESTIGATING</option>
                <option value="CONTAINMENT" className="bg-soc-900">CONTAINMENT</option>
                <option value="ERADICATION" className="bg-soc-900">ERADICATION</option>
                <option value="RECOVERY" className="bg-soc-900">RECOVERY</option>
                <option value="MONITORING" className="bg-soc-900">MONITORING</option>
                <option value="RESOLVED" className="bg-soc-900">RESOLVED</option>
                <option value="CLOSED" className="bg-soc-900">CLOSED</option>
              </select>
            </div>

            <div className="flex items-center gap-1.5 text-xs font-mono text-soc-400 bg-soc-950 px-2.5 py-1.5 rounded border border-soc-750">
              <span>Priority:</span>
              <select
                value={priorityFilter}
                onChange={(e) => setPriorityFilter(e.target.value)}
                className="bg-transparent text-white font-mono focus:outline-none cursor-pointer"
              >
                <option value="ALL" className="bg-soc-900">ALL</option>
                <option value="P1_CRITICAL" className="bg-soc-900">P1_CRITICAL</option>
                <option value="P2_HIGH" className="bg-soc-900">P2_HIGH</option>
                <option value="P3_MEDIUM" className="bg-soc-900">P3_MEDIUM</option>
                <option value="P4_LOW" className="bg-soc-900">P4_LOW</option>
              </select>
            </div>

            <div className="flex items-center gap-1.5 text-xs font-mono text-soc-400 bg-soc-950 px-2.5 py-1.5 rounded border border-soc-750">
              <span>Verdict:</span>
              <select
                value={verdictFilter}
                onChange={(e) => setVerdictFilter(e.target.value)}
                className="bg-transparent text-white font-mono focus:outline-none cursor-pointer"
              >
                <option value="ALL" className="bg-soc-900">ALL</option>
                <option value="MALICIOUS" className="bg-soc-900">MALICIOUS</option>
                <option value="SUSPICIOUS" className="bg-soc-900">SUSPICIOUS</option>
                <option value="BENIGN" className="bg-soc-900">BENIGN</option>
                <option value="FALSE_POSITIVE" className="bg-soc-900">FALSE_POSITIVE</option>
                <option value="INCONCLUSIVE" className="bg-soc-900">INCONCLUSIVE</option>
              </select>
            </div>
          </div>
        </div>
      </Card>

      {/* Case Table */}
      <Card noPadding className="border-soc-800 overflow-hidden">
        {error && (
          <div className="p-4 bg-red-950/40 border-b border-red-900 text-xs font-mono text-red-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            {error}
          </div>
        )}

        {loading ? (
          <div className="p-12 text-center text-soc-400 font-mono text-xs flex flex-col items-center justify-center gap-3">
            <RefreshCw className="w-6 h-6 animate-spin text-blue-400" />
            Loading SOC Incident Registry...
          </div>
        ) : cases.length === 0 ? (
          <div className="p-12 text-center text-soc-400 font-mono text-xs flex flex-col items-center justify-center gap-3">
            <FolderLock className="w-8 h-8 text-soc-600" />
            <span>No incident cases found matching the current filters.</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-soc-950/80 border-b border-soc-800 text-soc-400 font-mono uppercase text-[11px]">
                  <th className="py-3 px-4 font-semibold">Case ID</th>
                  <th className="py-3 px-4 font-semibold">Title & Incident Scope</th>
                  <th className="py-3 px-3 font-semibold">Priority</th>
                  <th className="py-3 px-3 font-semibold">Lifecycle Stage</th>
                  <th className="py-3 px-3 font-semibold">Verdict</th>
                  <th className="py-3 px-3 font-semibold">Risk Score</th>
                  <th className="py-3 px-3 font-semibold">Analyst</th>
                  <th className="py-3 px-3 font-semibold">Blockchain</th>
                  <th className="py-3 px-4 text-right font-semibold">Workbench</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-850">
                {cases.map((c) => (
                  <tr
                    key={c.case_id}
                    onClick={() => navigate(`/cases/${c.case_id}`)}
                    className="hover:bg-soc-850/50 cursor-pointer transition-colors group"
                  >
                    <td className="py-3.5 px-4 font-mono font-bold text-blue-400 whitespace-nowrap">
                      <span className="flex items-center gap-1.5">
                        <FolderLock className="w-3.5 h-3.5 opacity-70" />
                        {c.case_id}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 max-w-xs md:max-w-md">
                      <div className="font-medium text-soc-100 group-hover:text-white truncate">
                        {c.title}
                      </div>
                      <div className="text-[11px] text-soc-400 flex items-center gap-2 mt-0.5">
                        {c.investigation_id && (
                          <span className="font-mono text-blue-400/80">
                            ref: {c.investigation_id}
                          </span>
                        )}
                        {c.primary_indicator && (
                          <span className="font-mono text-soc-500 truncate max-w-[200px]">
                            ioc: {c.primary_indicator}
                          </span>
                        )}
                      </div>
                      {c.tags && c.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1.5">
                          {c.tags.slice(0, 3).map((tag, idx) => (
                            <span
                              key={idx}
                              className="px-1.5 py-0.2 rounded bg-soc-800 text-soc-400 text-[10px] font-mono border border-soc-750"
                            >
                              #{tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>

                    <td className="py-3.5 px-3 whitespace-nowrap">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[11px] font-mono font-semibold border ${getPriorityBadgeClass(
                          c.priority
                        )}`}
                      >
                        {c.priority.replace('P1_', 'P1: ').replace('P2_', 'P2: ').replace('P3_', 'P3: ').replace('P4_', 'P4: ')}
                      </span>
                    </td>

                    <td className="py-3.5 px-3 whitespace-nowrap">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[11px] font-mono font-semibold border ${getStatusBadgeClass(
                          c.status
                        )}`}
                      >
                        {c.status}
                      </span>
                    </td>

                    <td className="py-3.5 px-3 whitespace-nowrap">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[11px] font-mono font-semibold border ${getVerdictBadgeClass(
                          c.verdict
                        )}`}
                      >
                        {c.verdict}
                      </span>
                    </td>

                    <td className="py-3.5 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <div className="w-12 bg-soc-950 rounded-full h-1.5 overflow-hidden border border-soc-800">
                          <div
                            className={`h-full ${
                              c.risk_score >= 80
                                ? 'bg-red-500'
                                : c.risk_score >= 50
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.min(100, c.risk_score)}%` }}
                          />
                        </div>
                        <span
                          className={`font-mono font-bold text-xs ${
                            c.risk_score >= 80
                              ? 'text-red-400'
                              : c.risk_score >= 50
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {c.risk_score}
                        </span>
                      </div>
                    </td>

                    <td className="py-3.5 px-3 whitespace-nowrap text-soc-300 font-mono text-[11px]">
                      <div className="flex items-center gap-1.5">
                        <User className="w-3.5 h-3.5 text-soc-500" />
                        <span>{c.assigned_analyst}</span>
                      </div>
                    </td>

                    <td className="py-3.5 px-3 whitespace-nowrap font-mono text-[11px]">
                      {c.blockchain_verified ? (
                        <span className="flex items-center gap-1 text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/80">
                          <FileCheck2 className="w-3 h-3" />
                          ANCHORED
                        </span>
                      ) : (
                        <span className="text-soc-500">PENDING</span>
                      )}
                    </td>

                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/cases/${c.case_id}`);
                        }}
                        className="px-2.5 py-1 bg-soc-800 hover:bg-blue-600 hover:text-white text-soc-300 border border-soc-700 rounded text-xs font-mono inline-flex items-center gap-1 transition-colors"
                      >
                        Workbench
                        <ChevronRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Modal: Create Incident Case */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-soc-900 border border-soc-750 rounded-lg max-w-xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-soc-800 pb-3">
              <div className="flex items-center gap-2">
                <FolderLock className="w-5 h-5 text-blue-400" />
                <h2 className="text-base font-bold font-mono text-white">Create Incident Case</h2>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="text-soc-400 hover:text-white font-mono text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-soc-300 mb-1">
                  Incident Title *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Malicious Executive Phishing Campaign - Financial Fraud"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-soc-300 mb-1">
                  Incident Description
                </label>
                <textarea
                  rows={3}
                  placeholder="Summarize forensic findings, target recipient, attacker vector..."
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-soc-300 mb-1">
                    Inherit from Investigation ID (Optional)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. INV-2026-00001"
                    value={formData.investigation_id}
                    onChange={(e) => setFormData({ ...formData, investigation_id: e.target.value })}
                    className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-soc-300 mb-1">
                    Initial Priority
                  </label>
                  <select
                    value={formData.priority}
                    onChange={(e) => setFormData({ ...formData, priority: e.target.value as CasePriority })}
                    className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="P1_CRITICAL">P1_CRITICAL (Active Breach / High Impact)</option>
                    <option value="P2_HIGH">P2_HIGH (Weaponized Phishing / Malware)</option>
                    <option value="P3_MEDIUM">P3_MEDIUM (Suspicious Anomalies / SPF Failure)</option>
                    <option value="P4_LOW">P4_LOW (Low Risk / Routine Triage)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-soc-300 mb-1">
                    Assigned SOC Analyst
                  </label>
                  <input
                    type="text"
                    value={formData.assigned_analyst}
                    onChange={(e) => setFormData({ ...formData, assigned_analyst: e.target.value })}
                    className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-soc-300 mb-1">
                    Tags (Comma-separated)
                  </label>
                  <input
                    type="text"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    className="w-full px-3 py-2 bg-soc-950 border border-soc-750 rounded text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-soc-800">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 bg-soc-800 hover:bg-soc-750 text-soc-300 rounded text-xs font-mono"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-mono font-semibold flex items-center gap-2"
                >
                  {submitting ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    'Create Incident Case'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
