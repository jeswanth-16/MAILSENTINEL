import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Card } from '../components/common/Card';
import { EmailForensicResult, AuthenticationVerdict } from '../types/emailForensics';
import {
  ThreatAssessmentResult,
  ThreatSeverityLevel,
} from '../types/threatAssessment';
import { uploadAndAnalyzeEmail } from '../services/emailService';
import { assessThreat } from '../services/threatService';
import { createSampleEmlFile, createCleanEmlFile } from '../data/sampleEml';
import {
  MailSearch,
  UploadCloud,
  FileCode,
  Hash,
  Paperclip,
  AlertTriangle,
  Copy,
  Check,
  RotateCcw,
  Activity,
  Zap,
  Layers,
  GitCommit,
  Share2,
  Link2,
  ShieldCheck
} from 'lucide-react';


export const EmailAnalyzerPage: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [loadingStep, setLoadingStep] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [forensicResult, setForensicResult] = useState<EmailForensicResult | null>(null);
  const [threatAssessment, setThreatAssessment] = useState<ThreatAssessmentResult | null>(null);
  const [activeTab, setActiveTab] = useState<
    'overview' | 'auth' | 'route' | 'ips' | 'urls' | 'attachments' | 'body'
  >('overview');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const executeFullTriage = async (fileToAnalyze: File) => {
    setLoading(true);
    setError(null);
    setForensicResult(null);
    setThreatAssessment(null);

    try {
      setLoadingStep('Uploading raw .EML container...');
      await new Promise((r) => setTimeout(r, 150));

      setLoadingStep('Parsing RFC 5322 structure & headers...');
      const forensicData = await uploadAndAnalyzeEmail(fileToAnalyze);
      setForensicResult(forensicData);

      setLoadingStep('Detecting observable threat indicators & anomalies...');
      await new Promise((r) => setTimeout(r, 200));

      setLoadingStep('Executing deterministic risk scoring & category caps...');
      const threatData = await assessThreat(forensicData);

      setLoadingStep('Compiling evidence-backed explanations...');
      await new Promise((r) => setTimeout(r, 150));

      setThreatAssessment(threatData);
    } catch (err: any) {
      setError(err.message || 'Forensic and threat assessment pipeline failed.');
    } finally {
      setLoading(false);
      setLoadingStep('');
    }
  };

  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      executeFullTriage(file);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      executeFullTriage(file);
    }
  };

  const handleLoadSamplePhishing = () => {
    const sample = createSampleEmlFile();
    setSelectedFile(sample);
    executeFullTriage(sample);
  };

  const handleLoadSampleClean = () => {
    const sample = createCleanEmlFile();
    setSelectedFile(sample);
    executeFullTriage(sample);
  };

  const getVerdictBadgeVariant = (verdict: AuthenticationVerdict) => {
    switch (verdict) {
      case 'PASS':
        return 'bg-emerald-950/80 text-emerald-400 border-emerald-800';
      case 'FAIL':
      case 'PERMERROR':
        return 'bg-red-950/80 text-red-400 border-red-800';
      case 'SOFTFAIL':
      case 'TEMPERROR':
        return 'bg-amber-950/80 text-amber-400 border-amber-800';
      case 'NEUTRAL':
      case 'NONE':
        return 'bg-blue-950/80 text-blue-400 border-blue-800';
      case 'NOT_AVAILABLE':
      default:
        return 'bg-soc-800 text-soc-400 border-soc-700';
    }
  };

  const getSeverityBadgeClass = (severity: ThreatSeverityLevel) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-950/90 text-red-400 border-red-800 font-bold';
      case 'HIGH':
        return 'bg-orange-950/90 text-orange-400 border-orange-800 font-bold';
      case 'MEDIUM':
        return 'bg-amber-950/90 text-amber-400 border-amber-800 font-bold';
      case 'LOW':
        return 'bg-blue-950/90 text-blue-400 border-blue-800 font-semibold';
      case 'CLEAN':
        return 'bg-emerald-950/90 text-emerald-400 border-emerald-800 font-semibold';
    }
  };

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <MailSearch className="w-5 h-5 text-blue-400" />
            <span>EMAIL_THREAT_ANALYSIS_&_RISK_ENGINE</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Deterministic forensic evidence triage + Explainable threat scoring & observable indicator reasoning.
          </p>
        </div>

        {(forensicResult || threatAssessment) && (
          <button
            onClick={() => {
              setForensicResult(null);
              setThreatAssessment(null);
              setSelectedFile(null);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-soc-800 hover:bg-soc-700 text-soc-200 text-xs font-mono border border-soc-700 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Triage Another Case</span>
          </button>
        )}
      </div>

      {/* Initial Upload Container */}
      {!forensicResult && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-4">
            <Card title="Raw .EML Upload & Forensic Intake">
              <div
                onDragOver={(e) => e.preventDefault()}
                onDrop={handleFileDrop}
                className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors bg-soc-950/40 cursor-pointer ${
                  loading
                    ? 'border-blue-500/80 bg-blue-950/10'
                    : 'border-soc-700 hover:border-blue-500/80'
                }`}
              >
                <input
                  type="file"
                  id="eml-upload"
                  accept=".eml,.msg,.txt"
                  disabled={loading}
                  onChange={handleFileChange}
                  className="hidden"
                />

                {loading ? (
                  <div className="space-y-4 py-4">
                    <Activity className="w-10 h-10 mx-auto text-blue-400 animate-spin" />
                    <div>
                      <div className="text-sm font-semibold font-mono text-soc-100">
                        EXECUTING FORENSIC & THREAT PIPELINE
                      </div>
                      <p className="text-xs text-blue-400 font-mono mt-1">{loadingStep}</p>
                    </div>
                  </div>
                ) : (
                  <label htmlFor="eml-upload" className="cursor-pointer block space-y-3">
                    <div className="w-12 h-12 mx-auto rounded-full bg-blue-950/80 border border-blue-800/80 flex items-center justify-center text-blue-400">
                      <UploadCloud className="w-6 h-6" />
                    </div>
                    <div>
                      <span className="text-sm font-semibold text-soc-100">
                        {selectedFile ? selectedFile.name : 'Select or Drop Suspicious .EML File'}
                      </span>
                      <p className="text-xs text-soc-500 mt-1 font-mono">
                        RFC 5322 MIME Container • Max: 25MB • Zero-Execution Sandbox
                      </p>
                    </div>
                  </label>
                )}
              </div>

              {/* Sample Loaders */}
              <div className="mt-4 flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-soc-800 text-xs font-mono">
                <div className="flex flex-wrap items-center gap-3">
                  <button
                    onClick={handleLoadSamplePhishing}
                    disabled={loading}
                    className="text-xs text-red-400 hover:text-red-300 underline font-mono flex items-center gap-1"
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    <span>Load Phishing Wire Fraud .EML (High Risk Demo)</span>
                  </button>

                  <button
                    onClick={handleLoadSampleClean}
                    disabled={loading}
                    className="text-xs text-emerald-400 hover:text-emerald-300 underline font-mono flex items-center gap-1"
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    <span>Load Clean Verified .EML (Benign Demo)</span>
                  </button>
                </div>

                <span className="text-soc-500 text-[11px]">
                  Engine: Python email.policy.default + SHA-256
                </span>
              </div>
            </Card>

            {error && (
              <div className="p-4 bg-red-950/60 border border-red-800 rounded font-mono text-xs text-red-300 flex items-start gap-3">
                <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <strong className="block text-red-200">FORENSIC_TRIAGE_ERROR:</strong>
                  <span>{error}</span>
                </div>
              </div>
            )}
          </div>

          {/* Right Info Column */}
          <div className="space-y-4 font-mono text-xs">
            <Card title="Explainable Risk Architecture">
              <div className="space-y-3">
                <div className="text-soc-300">
                  <span className="text-emerald-400 font-semibold">Observable Evidence:</span> Risk
                  score is calculated from tangible artifacts (SPF/DKIM failures, lookalike domains, double
                  extensions, urgency keywords).
                </div>
                <div className="text-soc-300">
                  <span className="text-emerald-400 font-semibold">Controlled Caps:</span> Category
                  point caps prevent double-counting or unbounded point multiplication.
                </div>
                <div className="text-soc-300">
                  <span className="text-emerald-400 font-semibold">No Blind AI Verdicts:</span> AI
                  serves as semantic interpretation; deterministic security rules govern threat boundaries.
                </div>
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* ACTIVE CASE TRIAGE & THREAT ASSESSMENT */}
      {forensicResult && threatAssessment && (
        <div className="space-y-6">
          {/* SECTION 1: PROMINENT THREAT ASSESSMENT CONSOLE */}
          <div className="p-5 bg-soc-900 border border-soc-800 rounded-md shadow-md space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-soc-800/80 pb-4">
              {/* Left: Case Info */}
              <div>
                <div className="flex items-center gap-3">
                  <span className="text-base font-bold font-mono text-blue-400">
                    {threatAssessment.investigation_id}
                  </span>
                  <span className="text-xs font-mono text-soc-400">File: {forensicResult.file_name}</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-soc-950 text-soc-400 border border-soc-800 font-mono">
                    {(forensicResult.file_size_bytes / 1024).toFixed(1)} KB
                  </span>
                </div>
                <h2 className="text-sm font-semibold text-soc-100 font-sans mt-1">
                  {forensicResult.metadata.subject}
                </h2>
              </div>

              {/* Right: Confidence & AI status */}
              <div className="flex flex-col sm:flex-row sm:items-center gap-3 text-xs font-mono">
                <div className="px-3 py-1.5 bg-soc-950 rounded border border-soc-800">
                  <span className="text-soc-500 block text-[10px]">ANALYSIS CONFIDENCE:</span>
                  <span className="text-soc-200 font-bold">
                    {threatAssessment.confidence_percentage}% Certainty
                  </span>
                </div>
                <div className="px-3 py-1.5 bg-soc-950 rounded border border-soc-800">
                  <span className="text-soc-500 block text-[10px]">AI ENRICHMENT:</span>
                  <span className="text-cyan-400 font-medium">
                    {threatAssessment.ai_enrichment.available ? 'Active (Gemini)' : 'Deterministic Mode'}
                  </span>
                </div>
              </div>
            </div>

            {/* Score & Severity Hero Display */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Risk Gauge Card */}
              <div className="p-4 bg-soc-950 rounded border border-soc-800 flex items-center justify-between">
                <div>
                  <span className="text-[11px] font-mono text-soc-500 uppercase tracking-wider block">
                    Calculated Threat Score
                  </span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span
                      className={`text-4xl font-extrabold font-mono ${
                        threatAssessment.risk_score >= 75
                          ? 'text-threat-critical'
                          : threatAssessment.risk_score >= 50
                          ? 'text-threat-high'
                          : threatAssessment.risk_score >= 25
                          ? 'text-threat-medium'
                          : 'text-threat-clean'
                      }`}
                    >
                      {threatAssessment.risk_score}
                    </span>
                    <span className="text-xs font-mono text-soc-500">/ 100</span>
                  </div>
                </div>

                <div className="text-right space-y-1">
                  <span
                    className={`px-3 py-1 rounded border text-xs font-mono uppercase inline-block ${getSeverityBadgeClass(
                      threatAssessment.severity
                    )}`}
                  >
                    {threatAssessment.severity}
                  </span>
                  <div className="text-[10px] font-mono text-soc-500">SEVERITY LEVEL</div>
                </div>
              </div>

              {/* Classification Card */}
              <div className="p-4 bg-soc-950 rounded border border-soc-800 flex flex-col justify-between">
                <div>
                  <span className="text-[11px] font-mono text-soc-500 uppercase tracking-wider block">
                    Evidence-Based Classification
                  </span>
                  <span className="text-base font-bold font-mono text-soc-100 block mt-1">
                    {threatAssessment.classification.replace(/_/g, ' ')}
                  </span>
                </div>
                <div className="text-[11px] text-soc-400 font-mono mt-2 flex items-center gap-1">
                  <Zap className="w-3.5 h-3.5 text-blue-400" />
                  <span>{threatAssessment.indicators.length} observable indicator(s) identified</span>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="p-4 bg-soc-950 rounded border border-soc-800 flex flex-col justify-between">
                <span className="text-[11px] font-mono text-soc-500 uppercase tracking-wider block">
                  Threat Triage Summary
                </span>
                <p className="text-xs text-soc-300 font-sans leading-relaxed mt-1">
                  {threatAssessment.summary}
                </p>
              </div>
            </div>

            {/* Category Score Breakdown Bars */}
            <div className="p-4 bg-soc-950/60 rounded border border-soc-800 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between text-[11px] text-soc-400 uppercase font-semibold">
                <span>Controlled Category Risk Contributions</span>
                <span>Max Cap Normalization (0-100)</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {threatAssessment.category_breakdown.map((cat) => {
                  const pct = Math.min(100, Math.round((cat.capped_points / cat.max_cap) * 100));
                  return (
                    <div key={cat.category} className="p-2.5 bg-soc-900 border border-soc-800 rounded space-y-1.5">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-soc-300 font-medium truncate">{cat.category}</span>
                        <span
                          className={`font-mono font-bold ${
                            cat.capped_points > 0 ? 'text-amber-400' : 'text-soc-500'
                          }`}
                        >
                          {cat.capped_points}/{cat.max_cap}
                        </span>
                      </div>
                      <div className="w-full bg-soc-950 rounded-full h-1.5 overflow-hidden border border-soc-800">
                        <div
                          className={`h-full transition-all ${
                            pct >= 75
                              ? 'bg-red-500'
                              : pct >= 50
                              ? 'bg-orange-500'
                              : pct > 0
                              ? 'bg-amber-500'
                              : 'bg-soc-700'
                          }`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <div className="text-[10px] text-soc-500 flex justify-between">
                        <span>{cat.indicator_count} trigger(s)</span>
                        <span>{pct}% loaded</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Cross-Investigation Forensic Actions */}
            <div className="p-3 bg-soc-950 rounded border border-soc-800 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
              <span className="text-soc-400 font-semibold flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                <span>Next Forensic Investigation Workflows:</span>
              </span>
              <div className="flex flex-wrap items-center gap-2">
                <Link
                  to="/timeline"
                  className="px-3 py-1.5 bg-soc-900 hover:bg-soc-800 border border-soc-700 text-soc-200 rounded flex items-center gap-1.5 transition-colors"
                >
                  <GitCommit className="w-3.5 h-3.5 text-blue-400" />
                  <span>View Forensic Timeline</span>
                </Link>
                <Link
                  to="/graph"
                  className="px-3 py-1.5 bg-soc-900 hover:bg-soc-800 border border-soc-700 text-soc-200 rounded flex items-center gap-1.5 transition-colors"
                >
                  <Share2 className="w-3.5 h-3.5 text-purple-400" />
                  <span>Explore Attack Graph</span>
                </Link>
                <Link
                  to="/blockchain"
                  className="px-3 py-1.5 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700 text-cyan-300 rounded flex items-center gap-1.5 transition-colors font-bold shadow-sm"
                >
                  <Link2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Verify on Blockchain</span>
                </Link>
              </div>
            </div>
          </div>

          {/* SECTION 2: "WHY IS THIS SUSPICIOUS?" EVIDENCE-BACKED EXPLANATIONS & RECOMMENDATIONS */}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Observable Evidence Explanations */}
            <div className="lg:col-span-2 space-y-4">
              <Card
                title="Observable Threat Indicators & Evidence Breakdown"
                subtitle="Detailed rationale explaining why each finding contributed to the risk score"
              >
                {threatAssessment.explanations.length === 0 ? (
                  <div className="p-6 text-center text-xs font-mono text-soc-500">
                    No malicious or suspicious indicators detected. Email conforms to clean standards.
                  </div>
                ) : (
                  <div className="space-y-3 font-mono text-xs">
                    {threatAssessment.explanations.map((exp, idx) => (
                      <div
                        key={exp.indicator_id}
                        className="p-3 bg-soc-950 border border-soc-800 rounded space-y-2 hover:border-soc-700 transition-colors"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="w-5 h-5 rounded-full bg-blue-950 border border-blue-800 flex items-center justify-center text-[10px] font-bold text-blue-400 flex-shrink-0">
                              {idx + 1}
                            </span>
                            <span className="font-semibold text-soc-100 font-sans text-xs">
                              {exp.title}
                            </span>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-soc-900 text-soc-400 border border-soc-800">
                              {exp.category}
                            </span>
                          </div>
                          <span className="px-2 py-0.5 rounded bg-red-950/80 text-red-300 border border-red-800/80 font-bold text-[11px] whitespace-nowrap">
                            +{exp.score_contribution} pts
                          </span>
                        </div>

                        {/* Observable Evidence String */}
                        <div className="p-2 bg-soc-900/90 rounded border border-soc-800 text-[11px] text-soc-300 flex items-start gap-2">
                          <strong className="text-soc-500 flex-shrink-0">EVIDENCE:</strong>
                          <span className="text-amber-300 select-all font-mono">{exp.evidence}</span>
                        </div>

                        {/* Technical Rationale */}
                        <p className="text-[11px] text-soc-400 leading-relaxed font-sans">
                          {exp.rationale}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>

            {/* Right 1 Col: Defensive Recommendations */}
            <div className="space-y-4 font-mono text-xs">
              <Card title="Actionable Defensive Guidance" subtitle="Prescribed SOC containment measures">
                <div className="space-y-3">
                  {threatAssessment.recommendations.map((rec, i) => (
                    <div
                      key={i}
                      className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-soc-200 text-xs font-sans">
                          {rec.action}
                        </span>
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded border font-mono font-bold ${
                            rec.priority === 'HIGH'
                              ? 'bg-red-950 text-red-400 border-red-800'
                              : rec.priority === 'MEDIUM'
                              ? 'bg-amber-950 text-amber-400 border-amber-800'
                              : 'bg-blue-950 text-blue-400 border-blue-800'
                          }`}
                        >
                          {rec.priority}
                        </span>
                      </div>
                      <p className="text-[11px] text-soc-400 font-sans leading-relaxed">
                        {rec.guidance}
                      </p>
                    </div>
                  ))}
                </div>
              </Card>

              {/* SHA-256 Digest Proof Banner */}
              <div className="p-3.5 bg-soc-900 border border-soc-800 rounded space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-soc-400 text-[11px] flex items-center gap-1 font-semibold">
                    <Hash className="w-3.5 h-3.5 text-cyan-400" />
                    <span>CRYPTOGRAPHIC EVIDENCE PROOF</span>
                  </span>
                  <button
                    onClick={() => handleCopy(forensicResult.sha256_digest, 'sub_digest')}
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 underline"
                  >
                    {copiedKey === 'sub_digest' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div className="p-1.5 bg-soc-950 rounded border border-soc-800 text-[10px] text-soc-300 truncate select-all">
                  {forensicResult.sha256_digest}
                </div>
              </div>
            </div>
          </div>

          {/* SECTION 3: UNDERLYING FORENSIC DATA TABS (STEP 5 PRESERVED) */}
          <div className="space-y-4 pt-4 border-t border-soc-800">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-semibold text-soc-400 uppercase tracking-wider flex items-center gap-2">
                <Layers className="w-4 h-4 text-blue-400" />
                <span>Underlying Forensic Inspection Vault</span>
              </h3>
            </div>

            {/* Navigation Sub-Tabs */}
            <div className="flex border-b border-soc-800 overflow-x-auto gap-1 font-mono text-xs">
              <button
                onClick={() => setActiveTab('overview')}
                className={`px-4 py-2.5 font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === 'overview'
                    ? 'border-blue-400 text-blue-400 bg-soc-900/60'
                    : 'border-transparent text-soc-400 hover:text-soc-200'
                }`}
              >
                1. Email Overview & Headers ({forensicResult.metadata.raw_headers_count})
              </button>
              <button
                onClick={() => setActiveTab('auth')}
                className={`px-4 py-2.5 font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === 'auth'
                    ? 'border-blue-400 text-blue-400 bg-soc-900/60'
                    : 'border-transparent text-soc-400 hover:text-soc-200'
                }`}
              >
                2. Authentication ({forensicResult.authentication.spf} / {forensicResult.authentication.dkim} / {forensicResult.authentication.dmarc})
              </button>
              <button
                onClick={() => setActiveTab('route')}
                className={`px-4 py-2.5 font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === 'route'
                    ? 'border-blue-400 text-blue-400 bg-soc-900/60'
                    : 'border-transparent text-soc-400 hover:text-soc-200'
                }`}
              >
                3. Mail Route ({forensicResult.received_chain.length} Hops)
              </button>
              <button
                onClick={() => setActiveTab('ips')}
                className={`px-4 py-2.5 font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === 'ips'
                    ? 'border-blue-400 text-blue-400 bg-soc-900/60'
                    : 'border-transparent text-soc-400 hover:text-soc-200'
                }`}
              >
                4. IP Entities ({forensicResult.ip_addresses.length})
              </button>
              <button
                onClick={() => setActiveTab('urls')}
                className={`px-4 py-2.5 font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === 'urls'
                    ? 'border-blue-400 text-blue-400 bg-soc-900/60'
                    : 'border-transparent text-soc-400 hover:text-soc-200'
                }`}
              >
                5. URLs & Domains ({forensicResult.urls.length} URLs / {forensicResult.domains.length} Domains)
              </button>
              <button
                onClick={() => setActiveTab('attachments')}
                className={`px-4 py-2.5 font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === 'attachments'
                    ? 'border-blue-400 text-blue-400 bg-soc-900/60'
                    : 'border-transparent text-soc-400 hover:text-soc-200'
                }`}
              >
                6. Attachments ({forensicResult.attachments.length})
              </button>
              <button
                onClick={() => setActiveTab('body')}
                className={`px-4 py-2.5 font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === 'body'
                    ? 'border-blue-400 text-blue-400 bg-soc-900/60'
                    : 'border-transparent text-soc-400 hover:text-soc-200'
                }`}
              >
                7. Body Analysis
              </button>
            </div>

            {/* TAB 1: Overview & Headers */}
            {activeTab === 'overview' && (
              <Card title="RFC 5322 Extracted Headers & Envelope Data">
                <div className="space-y-3 font-mono text-xs">
                  <div className="p-3 bg-soc-950 border border-soc-800 rounded space-y-2">
                    <div className="flex flex-col sm:flex-row sm:items-baseline gap-2">
                      <span className="text-soc-500 w-32 flex-shrink-0">Subject:</span>
                      <span className="text-soc-100 font-semibold font-sans text-sm">
                        {forensicResult.metadata.subject}
                      </span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:items-baseline gap-2">
                      <span className="text-soc-500 w-32 flex-shrink-0">From:</span>
                      <span className="text-blue-300 font-medium">{forensicResult.metadata.from_address}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:items-baseline gap-2">
                      <span className="text-soc-500 w-32 flex-shrink-0">To:</span>
                      <span className="text-soc-200">{forensicResult.metadata.to_addresses.join(', ')}</span>
                    </div>
                    {forensicResult.metadata.cc_addresses.length > 0 && (
                      <div className="flex flex-col sm:flex-row sm:items-baseline gap-2">
                        <span className="text-soc-500 w-32 flex-shrink-0">CC:</span>
                        <span className="text-soc-200">{forensicResult.metadata.cc_addresses.join(', ')}</span>
                      </div>
                    )}
                    {forensicResult.metadata.reply_to && (
                      <div className="flex flex-col sm:flex-row sm:items-baseline gap-2">
                        <span className="text-amber-400 w-32 flex-shrink-0">Reply-To:</span>
                        <span className="text-amber-300 font-bold">{forensicResult.metadata.reply_to}</span>
                      </div>
                    )}
                    {forensicResult.metadata.return_path && (
                      <div className="flex flex-col sm:flex-row sm:items-baseline gap-2">
                        <span className="text-soc-500 w-32 flex-shrink-0">Return-Path:</span>
                        <span className="text-soc-300">{forensicResult.metadata.return_path}</span>
                      </div>
                    )}
                    <div className="flex flex-col sm:flex-row sm:items-baseline gap-2">
                      <span className="text-soc-500 w-32 flex-shrink-0">Date Sent:</span>
                      <span className="text-soc-300">{forensicResult.metadata.date || 'Not specified'}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:items-baseline gap-2">
                      <span className="text-soc-500 w-32 flex-shrink-0">Message-ID:</span>
                      <span className="text-soc-400 select-all">{forensicResult.metadata.message_id || 'Not specified'}</span>
                    </div>
                    <div className="flex flex-col sm:flex-row sm:items-baseline gap-2">
                      <span className="text-soc-500 w-32 flex-shrink-0">Content-Type:</span>
                      <span className="text-soc-400">{forensicResult.metadata.content_type || 'text/plain'}</span>
                    </div>
                  </div>
                </div>
              </Card>
            )}

            {/* TAB 2: Authentication Analysis */}
            {activeTab === 'auth' && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                  {/* SPF Verdict */}
                  <div className="p-4 bg-soc-900 border border-soc-800 rounded space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-soc-300">SPF VERDICT</span>
                      <span
                        className={`px-2 py-0.5 rounded border text-xs font-bold ${getVerdictBadgeVariant(
                          forensicResult.authentication.spf
                        )}`}
                      >
                        {forensicResult.authentication.spf}
                      </span>
                    </div>
                    <p className="text-[11px] text-soc-400 leading-relaxed">
                      {forensicResult.authentication.spf_detail || 'Sender Policy Framework record evaluation.'}
                    </p>
                  </div>

                  {/* DKIM Verdict */}
                  <div className="p-4 bg-soc-900 border border-soc-800 rounded space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-soc-300">DKIM VERDICT</span>
                      <span
                        className={`px-2 py-0.5 rounded border text-xs font-bold ${getVerdictBadgeVariant(
                          forensicResult.authentication.dkim
                        )}`}
                      >
                        {forensicResult.authentication.dkim}
                      </span>
                    </div>
                    <p className="text-[11px] text-soc-400 leading-relaxed">
                      {forensicResult.authentication.dkim_detail || 'DomainKeys Identified Mail signature.'}
                    </p>
                  </div>

                  {/* DMARC Verdict */}
                  <div className="p-4 bg-soc-900 border border-soc-800 rounded space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-soc-300">DMARC VERDICT</span>
                      <span
                        className={`px-2 py-0.5 rounded border text-xs font-bold ${getVerdictBadgeVariant(
                          forensicResult.authentication.dmarc
                        )}`}
                      >
                        {forensicResult.authentication.dmarc}
                      </span>
                    </div>
                    <p className="text-[11px] text-soc-400 leading-relaxed">
                      {forensicResult.authentication.dmarc_detail || 'Domain-based Message Authentication alignment.'}
                    </p>
                  </div>
                </div>

                {forensicResult.authentication.raw_header && (
                  <Card title="Raw Authentication Header Trace">
                    <pre className="p-3 bg-soc-950 rounded border border-soc-800 text-[11px] font-mono text-soc-300 overflow-x-auto whitespace-pre-wrap">
                      {forensicResult.authentication.raw_header}
                    </pre>
                  </Card>
                )}
              </div>
            )}

            {/* TAB 3: Mail Route / Received Chain */}
            {activeTab === 'route' && (
              <Card
                title="Reconstructed SMTP Transit Chain (Chronological Order)"
                subtitle="Hop 1 is the initial sender relay; final hop is the receiving mailbox provider."
                noPadding
              >
                <div className="overflow-x-auto font-mono text-xs">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-soc-800 text-[11px] text-soc-400 uppercase bg-soc-950/60">
                        <th className="px-4 py-2.5">Hop</th>
                        <th className="px-4 py-2.5">From Host</th>
                        <th className="px-4 py-2.5">By Receiving MTA</th>
                        <th className="px-4 py-2.5">IP Address</th>
                        <th className="px-4 py-2.5">Protocol</th>
                        <th className="px-4 py-2.5">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-soc-800/60">
                      {forensicResult.received_chain.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="px-4 py-8 text-center text-soc-500">
                            No Received headers found in container.
                          </td>
                        </tr>
                      ) : (
                        forensicResult.received_chain.map((hop) => (
                          <tr key={hop.hop} className="hover:bg-soc-850/50">
                            <td className="px-4 py-3 font-bold text-blue-400 whitespace-nowrap">
                              Hop #{hop.hop}
                            </td>
                            <td className="px-4 py-3 text-soc-200">{hop.from_host || 'N/A'}</td>
                            <td className="px-4 py-3 text-soc-300">{hop.by_host || 'N/A'}</td>
                            <td className="px-4 py-3 text-cyan-300 font-semibold whitespace-nowrap">
                              {hop.ip || 'Not recorded'}
                            </td>
                            <td className="px-4 py-3 text-soc-400 whitespace-nowrap">{hop.protocol || 'SMTP'}</td>
                            <td className="px-4 py-3 text-soc-500 text-[11px] whitespace-nowrap">
                              {hop.timestamp || 'N/A'}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}

            {/* TAB 4: Extracted IP Entities */}
            {activeTab === 'ips' && (
              <Card title="Extracted IP Addresses & Header Contexts" noPadding>
                <div className="overflow-x-auto font-mono text-xs">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-soc-800 text-[11px] text-soc-400 uppercase bg-soc-950/60">
                        <th className="px-4 py-2.5">IP Address</th>
                        <th className="px-4 py-2.5">Source Header</th>
                        <th className="px-4 py-2.5">Context Description</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-soc-800/60">
                      {forensicResult.ip_addresses.length === 0 ? (
                        <tr>
                          <td colSpan={3} className="px-4 py-8 text-center text-soc-500">
                            No IP entities extracted.
                          </td>
                        </tr>
                      ) : (
                        forensicResult.ip_addresses.map((ipObj, idx) => (
                          <tr key={idx} className="hover:bg-soc-850/50">
                            <td className="px-4 py-3 font-bold text-cyan-300 whitespace-nowrap">
                              {ipObj.ip}
                            </td>
                            <td className="px-4 py-3 text-blue-400 whitespace-nowrap">{ipObj.source}</td>
                            <td className="px-4 py-3 text-soc-300">{ipObj.context}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}

            {/* TAB 5: Extracted URLs & Domains */}
            {activeTab === 'urls' && (
              <div className="space-y-4 font-mono text-xs">
                <Card title="Unique Extracted Domains" subtitle="Frequency of domains referenced in message body">
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {forensicResult.domains.map((dom, i) => (
                      <div
                        key={i}
                        className="p-3 bg-soc-950 border border-soc-800 rounded flex items-center justify-between"
                      >
                        <div className="truncate">
                          <span className="font-semibold text-soc-200 block truncate">{dom.domain}</span>
                          <span className="text-[10px] text-soc-500">
                            {dom.source_urls.length} distinct URL reference(s)
                          </span>
                        </div>
                        <span className="px-2 py-0.5 rounded bg-soc-800 text-soc-300 border border-soc-700 text-xs font-bold">
                          {dom.occurrence_count}x
                        </span>
                      </div>
                    ))}
                  </div>
                </Card>

                <Card title="Normalized URL Forensic Breakdown" noPadding>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-soc-800 text-[11px] text-soc-400 uppercase bg-soc-950/60">
                          <th className="px-4 py-2.5">Domain / Host</th>
                          <th className="px-4 py-2.5">Normalized URL</th>
                          <th className="px-4 py-2.5">Path & Query</th>
                          <th className="px-4 py-2.5">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-soc-800/60">
                        {forensicResult.urls.length === 0 ? (
                          <tr>
                            <td colSpan={4} className="px-4 py-8 text-center text-soc-500">
                              No embedded URLs found in message body.
                            </td>
                          </tr>
                        ) : (
                          forensicResult.urls.map((u, idx) => (
                            <tr key={idx} className="hover:bg-soc-850/50">
                              <td className="px-4 py-3 text-blue-400 font-semibold whitespace-nowrap">
                                {u.domain}
                                {u.port ? `:${u.port}` : ''}
                              </td>
                              <td className="px-4 py-3 text-soc-200 max-w-xs truncate select-all">
                                {u.normalized_url}
                              </td>
                              <td className="px-4 py-3 text-soc-400 truncate max-w-xs">
                                {u.path}
                                {u.query ? `?${u.query}` : ''}
                              </td>
                              <td className="px-4 py-3 text-soc-500 text-[11px] whitespace-nowrap">
                                <span className="px-1.5 py-0.5 rounded bg-soc-800 border border-soc-700">
                                  {u.source}
                                </span>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </Card>
              </div>
            )}

            {/* TAB 6: Attachments */}
            {activeTab === 'attachments' && (
              <Card title="Inspected Attachment Artifacts" noPadding>
                <div className="overflow-x-auto font-mono text-xs">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-soc-800 text-[11px] text-soc-400 uppercase bg-soc-950/60">
                        <th className="px-4 py-2.5">Filename</th>
                        <th className="px-4 py-2.5">Extension</th>
                        <th className="px-4 py-2.5">MIME Type</th>
                        <th className="px-4 py-2.5">Size</th>
                        <th className="px-4 py-2.5">SHA-256 Digest</th>
                        <th className="px-4 py-2.5 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-soc-800/60">
                      {forensicResult.attachments.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="px-4 py-8 text-center text-soc-500">
                            No file attachments or embedded payloads in this message.
                          </td>
                        </tr>
                      ) : (
                        forensicResult.attachments.map((att, idx) => (
                          <tr key={idx} className="hover:bg-soc-850/50">
                            <td className="px-4 py-3 font-semibold text-soc-200 flex items-center gap-2">
                              <Paperclip className="w-3.5 h-3.5 text-blue-400 flex-shrink-0" />
                              <span>{att.filename}</span>
                            </td>
                            <td className="px-4 py-3 text-amber-400 whitespace-nowrap">{att.extension}</td>
                            <td className="px-4 py-3 text-soc-400 whitespace-nowrap">{att.mime_type}</td>
                            <td className="px-4 py-3 text-soc-300 whitespace-nowrap">
                              {(att.size_bytes / 1024).toFixed(1)} KB ({att.size_bytes} bytes)
                            </td>
                            <td className="px-4 py-3 text-soc-300 text-[11px] truncate max-w-xs select-all">
                              {att.sha256}
                            </td>
                            <td className="px-4 py-3 text-right whitespace-nowrap">
                              <button
                                onClick={() => handleCopy(att.sha256, `att_${idx}`)}
                                className="px-2 py-1 bg-soc-800 hover:bg-soc-700 text-soc-300 rounded text-[11px] inline-flex items-center gap-1 transition-colors"
                              >
                                {copiedKey === `att_${idx}` ? (
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
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}

            {/* TAB 7: Body Analysis */}
            {activeTab === 'body' && (
              <div className="space-y-4 font-mono text-xs">
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                  <div className="p-3 bg-soc-900 border border-soc-800 rounded">
                    <span className="text-soc-500 text-[10px] block">WORDS</span>
                    <span className="text-base font-bold text-soc-100">{forensicResult.body_analysis.word_count}</span>
                  </div>
                  <div className="p-3 bg-soc-900 border border-soc-800 rounded">
                    <span className="text-soc-500 text-[10px] block">CHARACTERS</span>
                    <span className="text-base font-bold text-soc-100">{forensicResult.body_analysis.character_count}</span>
                  </div>
                  <div className="p-3 bg-soc-900 border border-soc-800 rounded">
                    <span className="text-soc-500 text-[10px] block">LINES</span>
                    <span className="text-base font-bold text-soc-100">{forensicResult.body_analysis.line_count}</span>
                  </div>
                  <div className="p-3 bg-soc-900 border border-soc-800 rounded">
                    <span className="text-soc-500 text-[10px] block">HTML PARTS</span>
                    <span className="text-base font-bold text-blue-400">
                      {forensicResult.body_analysis.has_html ? 'YES' : 'NO'}
                    </span>
                  </div>
                  <div className="p-3 bg-soc-900 border border-soc-800 rounded">
                    <span className="text-soc-500 text-[10px] block">LINKS DETECTED</span>
                    <span className="text-base font-bold text-cyan-400">{forensicResult.body_analysis.link_count}</span>
                  </div>
                </div>

                <Card
                  title="Normalized Plaintext Excerpt (Sanitized Sandbox Stream)"
                  action={
                    <button
                      onClick={() => handleCopy(forensicResult.body_analysis.normalized_text_preview, 'body_text')}
                      className="px-2 py-1 bg-soc-800 hover:bg-soc-700 text-soc-300 rounded text-[11px] flex items-center gap-1 font-mono transition-colors"
                    >
                      {copiedKey === 'body_text' ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Text</span>
                        </>
                      )}
                    </button>
                  }
                >
                  <pre className="p-4 bg-soc-950 rounded border border-soc-800 text-xs text-soc-300 font-mono whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto">
                    {forensicResult.body_analysis.normalized_text_preview || '(No body text extracted)'}
                  </pre>
                </Card>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
