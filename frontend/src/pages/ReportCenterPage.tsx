import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText,
  FileCode,
  Table,
  Archive,
  ShieldCheck,
  RefreshCw,
  Copy,
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  Eye,
  FileCheck2,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { fetchCases } from '../services/caseService';
import {
  generateReport,
  fetchReport,
  fetchManifest,
  verifyReportIntegrity,
  getReportPdfUrl,
  getReportJsonUrl,
  getIocsCsvUrl,
  getTimelineCsvUrl,
  getFindingsCsvUrl,
  getPackageZipUrl,
} from '../services/reportingService';
import {
  ForensicReport,
  ReportManifest,
  ReportType,
  VerifyReportResponse,
} from '../types/reporting';
import { IncidentCase } from '../types/cases';

export const ReportCenterPage: React.FC = () => {
  const navigate = useNavigate();

  const [cases, setCases] = useState<IncidentCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>('CASE-2026-00001');
  const [reportType, setReportType] = useState<ReportType>('FULL_INVESTIGATION');
  const [currentReport, setCurrentReport] = useState<ForensicReport | null>(null);
  const [manifest, setManifest] = useState<ReportManifest | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [generating, setGenerating] = useState<boolean>(false);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [verificationResult, setVerificationResult] = useState<VerifyReportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Load available cases
  useEffect(() => {
    const initCases = async () => {
      try {
        const res = await fetchCases({ limit: 50 });
        if (res.cases && res.cases.length > 0) {
          setCases(res.cases);
          setSelectedCaseId(res.cases[0].case_id);
        }
      } catch (err: any) {
        console.error('Failed to load cases:', err);
      }
    };
    initCases();
  }, []);

  // Load report for selected case
  const loadReportData = useCallback(async (caseId: string) => {
    setLoading(true);
    setError(null);
    setVerificationResult(null);
    try {
      const [rpt, man] = await Promise.all([
        fetchReport(caseId),
        fetchManifest(caseId).catch(() => null),
      ]);
      setCurrentReport(rpt);
      setManifest(man);
    } catch (err: any) {
      console.warn('Report not pre-generated, creating on demand:', err);
      try {
        const generated = await generateReport(caseId, { report_type: reportType });
        setCurrentReport(generated);
        const man = await fetchManifest(caseId).catch(() => null);
        setManifest(man);
      } catch (genErr: any) {
        setError(genErr.message || 'Failed to generate report');
      }
    } finally {
      setLoading(false);
    }
  }, [reportType]);

  useEffect(() => {
    if (selectedCaseId) {
      loadReportData(selectedCaseId);
    }
  }, [selectedCaseId, loadReportData]);

  const handleGenerateReport = async () => {
    if (!selectedCaseId) return;
    setGenerating(true);
    setError(null);
    setVerificationResult(null);
    try {
      const rpt = await generateReport(selectedCaseId, {
        report_type: reportType,
        generated_by: 'SOC Security Lead Analyst',
        include_ai_assessment: true,
      });
      setCurrentReport(rpt);
      const man = await fetchManifest(selectedCaseId).catch(() => null);
      setManifest(man);
    } catch (err: any) {
      setError(err.message || 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  const handleVerifyReport = async () => {
    if (!currentReport) return;
    setVerifying(true);
    try {
      const res = await verifyReportIntegrity(currentReport.metadata.report_id);
      setVerificationResult(res);
    } catch (err: any) {
      alert(`Verification failed: ${err.message}`);
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Copied SHA-256 to clipboard: ' + text);
  };

  return (
    <div className="space-y-6">
      {/* Header & Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-soc-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-blue-950/40 border border-blue-800/60 text-blue-400">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold font-mono tracking-wider text-white">
                FORENSIC REPORT CENTER & EVIDENCE EXPORT
              </h1>
              <p className="text-xs text-soc-400 font-mono mt-0.5">
                Multi-format Digital Forensics Reporting, Cryptographic Evidence Packages & Tamper-Proof Audit Records
              </p>
            </div>
          </div>
        </div>

        {/* View Interactive Report Link */}
        <div className="flex items-center gap-2">
          {currentReport && (
            <button
              onClick={() => navigate(`/reports/view/${selectedCaseId}`)}
              className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-mono font-medium flex items-center gap-2 transition-colors shadow-sm"
            >
              <Eye className="w-4 h-4" />
              Open Interactive Report
            </button>
          )}
        </div>
      </div>

      {/* Control Toolbar */}
      <Card noPadding className="border-soc-800 bg-soc-900/80">
        <div className="p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 font-mono text-xs">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 bg-soc-950 px-3 py-1.5 rounded border border-soc-750">
              <span className="text-soc-500 uppercase text-[10px]">Select Incident Case:</span>
              <select
                value={selectedCaseId}
                onChange={(e) => setSelectedCaseId(e.target.value)}
                className="bg-transparent text-white font-mono focus:outline-none cursor-pointer"
              >
                {cases.map((c) => (
                  <option key={c.case_id} value={c.case_id} className="bg-soc-900">
                    {c.case_id} - {c.title.slice(0, 35)}...
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-2 bg-soc-950 px-3 py-1.5 rounded border border-soc-750">
              <span className="text-soc-500 uppercase text-[10px]">Report Format:</span>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value as ReportType)}
                className="bg-transparent text-white font-mono focus:outline-none cursor-pointer"
              >
                <option value="FULL_INVESTIGATION" className="bg-soc-900">FULL INVESTIGATION (All 26 Sections)</option>
                <option value="EXECUTIVE" className="bg-soc-900">EXECUTIVE SUMMARY</option>
                <option value="FORENSIC" className="bg-soc-900">TECHNICAL FORENSIC AUDIT</option>
                <option value="INCIDENT_RESPONSE" className="bg-soc-900">INCIDENT RESPONSE ACTION PLAN</option>
              </select>
            </div>
          </div>

          <button
            onClick={handleGenerateReport}
            disabled={generating}
            className="px-4 py-2 bg-soc-800 hover:bg-soc-750 text-soc-100 border border-soc-700 rounded text-xs font-mono font-semibold flex items-center justify-center gap-2 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${generating ? 'animate-spin text-blue-400' : ''}`} />
            {generating ? 'Generating Forensic Report...' : 'Re-Generate Report'}
          </button>
        </div>
      </Card>

      {error && (
        <div className="p-4 bg-red-950/40 border border-red-800 rounded font-mono text-xs text-red-300 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400" />
          {error}
        </div>
      )}

      {loading ? (
        <div className="p-16 text-center text-soc-400 font-mono text-xs flex flex-col items-center justify-center gap-3">
          <RefreshCw className="w-8 h-8 animate-spin text-blue-400" />
          <span>Assembling Forensic Evidence & Compiling Report...</span>
        </div>
      ) : currentReport ? (
        <div className="space-y-6">
          {/* Metadata & Risk Strip */}
          <Card noPadding className="border-soc-800 bg-soc-950/80">
            <div className="p-4 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-4 font-mono text-xs">
              <div>
                <div className="text-soc-500 uppercase text-[10px]">REPORT ID / VER</div>
                <div className="mt-1 font-bold text-blue-400">
                  {currentReport.metadata.report_id} <span className="text-soc-400 font-normal">v{currentReport.metadata.version}</span>
                </div>
              </div>

              <div>
                <div className="text-soc-500 uppercase text-[10px]">ASSOCIATED CASE</div>
                <div className="mt-1 text-soc-100 font-bold">
                  {currentReport.metadata.case_id}
                </div>
              </div>

              <div>
                <div className="text-soc-500 uppercase text-[10px]">REPORT TYPE</div>
                <div className="mt-1 text-amber-300 font-semibold truncate">
                  {currentReport.metadata.report_type}
                </div>
              </div>

              <div>
                <div className="text-soc-500 uppercase text-[10px]">AUTHORITATIVE RISK</div>
                <div className="mt-1 flex items-center gap-1.5 font-bold">
                  <span
                    className={
                      currentReport.metadata.risk_score >= 80
                        ? 'text-red-400'
                        : currentReport.metadata.risk_score >= 50
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }
                  >
                    {currentReport.metadata.risk_score}/100
                  </span>
                  <span className="text-[10px] text-soc-500 font-normal">
                    ({currentReport.metadata.classification})
                  </span>
                </div>
              </div>

              <div>
                <div className="text-soc-500 uppercase text-[10px]">BLOCKCHAIN PROOF</div>
                <div className="mt-1">
                  <span className="inline-flex items-center gap-1 text-cyan-400 font-bold bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800 text-[10px]">
                    <FileCheck2 className="w-3 h-3" />
                    {currentReport.metadata.blockchain_status} #B{currentReport.metadata.blockchain_block_number || 104}
                  </span>
                </div>
              </div>

              <div>
                <div className="text-soc-500 uppercase text-[10px]">GENERATED TIMESTAMP</div>
                <div className="mt-1 text-soc-400 text-[11px]">
                  {new Date(currentReport.metadata.generated_at).toLocaleString()}
                </div>
              </div>
            </div>

            {/* Checksum Strip */}
            <div className="px-4 py-2 bg-soc-900/60 border-t border-soc-800/80 flex flex-wrap items-center justify-between gap-2 font-mono text-xs">
              <div className="flex items-center gap-2 text-[11px] text-soc-400">
                <span className="text-soc-500 uppercase">Evidence SHA-256:</span>
                <span className="text-soc-200 break-all">{currentReport.metadata.evidence_sha256}</span>
                <button
                  onClick={() => copyToClipboard(currentReport.metadata.evidence_sha256)}
                  className="text-soc-500 hover:text-white"
                  title="Copy SHA-256"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="flex items-center gap-2 text-[11px] text-soc-400">
                <span className="text-soc-500 uppercase">Report Digest:</span>
                <span className="text-cyan-300 break-all">
                  {(currentReport.metadata.report_sha256 || '').slice(0, 24)}...
                </span>
              </div>
            </div>
          </Card>

          {/* Verification Banner */}
          {verificationResult && (
            <div
              className={`p-4 rounded border font-mono text-xs flex items-center justify-between gap-3 ${
                verificationResult.verified
                  ? 'bg-cyan-950/40 border-cyan-800 text-cyan-300'
                  : 'bg-red-950/40 border-red-800 text-red-300'
              }`}
            >
              <div className="flex items-center gap-2">
                {verificationResult.verified ? (
                  <CheckCircle2 className="w-5 h-5 text-cyan-400" />
                ) : (
                  <AlertOctagon className="w-5 h-5 text-red-400" />
                )}
                <div>
                  <div className="font-bold">{verificationResult.message}</div>
                  <div className="text-[11px] text-soc-400 mt-0.5">
                    Stored Digest: <code className="text-soc-200">{verificationResult.stored_hash}</code> | Calculated: <code className="text-soc-200">{verificationResult.calculated_hash}</code>
                  </div>
                </div>
              </div>
              <span className="text-[10px] text-soc-500">
                {new Date(verificationResult.verification_timestamp).toLocaleTimeString()}
              </span>
            </div>
          )}

          {/* Export & Action Buttons */}
          <Card title="Official Export & Download Center" className="border-soc-800">
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2.5 font-mono text-xs">
              {/* 1. PDF Download */}
              <a
                href={getReportPdfUrl(selectedCaseId)}
                download
                className="p-3 bg-soc-950 hover:bg-blue-900/30 border border-soc-750 hover:border-blue-500 rounded flex flex-col items-center text-center gap-2 transition-all group"
              >
                <FileText className="w-5 h-5 text-red-400 group-hover:scale-110 transition-transform" />
                <div>
                  <div className="font-bold text-white text-[11px]">DOWNLOAD PDF</div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Official SOC Report</div>
                </div>
              </a>

              {/* 2. JSON Export */}
              <a
                href={getReportJsonUrl(selectedCaseId)}
                download
                className="p-3 bg-soc-950 hover:bg-blue-900/30 border border-soc-750 hover:border-blue-500 rounded flex flex-col items-center text-center gap-2 transition-all group"
              >
                <FileCode className="w-5 h-5 text-blue-400 group-hover:scale-110 transition-transform" />
                <div>
                  <div className="font-bold text-white text-[11px]">EXPORT JSON</div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Machine-Readable</div>
                </div>
              </a>

              {/* 3. IOCs CSV */}
              <a
                href={getIocsCsvUrl(selectedCaseId)}
                download
                className="p-3 bg-soc-950 hover:bg-blue-900/30 border border-soc-750 hover:border-blue-500 rounded flex flex-col items-center text-center gap-2 transition-all group"
              >
                <Table className="w-5 h-5 text-amber-400 group-hover:scale-110 transition-transform" />
                <div>
                  <div className="font-bold text-white text-[11px]">IOCs CSV</div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Threat Indicators</div>
                </div>
              </a>

              {/* 4. Timeline CSV */}
              <a
                href={getTimelineCsvUrl(selectedCaseId)}
                download
                className="p-3 bg-soc-950 hover:bg-blue-900/30 border border-soc-750 hover:border-blue-500 rounded flex flex-col items-center text-center gap-2 transition-all group"
              >
                <Table className="w-5 h-5 text-purple-400 group-hover:scale-110 transition-transform" />
                <div>
                  <div className="font-bold text-white text-[11px]">TIMELINE CSV</div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Chronology Log</div>
                </div>
              </a>

              {/* 5. Findings CSV */}
              <a
                href={getFindingsCsvUrl(selectedCaseId)}
                download
                className="p-3 bg-soc-950 hover:bg-blue-900/30 border border-soc-750 hover:border-blue-500 rounded flex flex-col items-center text-center gap-2 transition-all group"
              >
                <Table className="w-5 h-5 text-emerald-400 group-hover:scale-110 transition-transform" />
                <div>
                  <div className="font-bold text-white text-[11px]">FINDINGS CSV</div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Security Audit Log</div>
                </div>
              </a>

              {/* 6. Evidence Package ZIP */}
              <a
                href={getPackageZipUrl(selectedCaseId)}
                download
                className="p-3 bg-soc-950 hover:bg-blue-900/30 border border-soc-750 hover:border-blue-500 rounded flex flex-col items-center text-center gap-2 transition-all group"
              >
                <Archive className="w-5 h-5 text-cyan-400 group-hover:scale-110 transition-transform" />
                <div>
                  <div className="font-bold text-white text-[11px]">EVIDENCE ZIP</div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Full Package + Manifest</div>
                </div>
              </a>

              {/* 7. Verify Integrity */}
              <button
                onClick={handleVerifyReport}
                disabled={verifying}
                className="p-3 bg-soc-950 hover:bg-cyan-900/30 border border-soc-750 hover:border-cyan-500 rounded flex flex-col items-center text-center gap-2 transition-all group"
              >
                <ShieldCheck className={`w-5 h-5 text-cyan-400 group-hover:scale-110 transition-transform ${verifying ? 'animate-spin' : ''}`} />
                <div>
                  <div className="font-bold text-cyan-300 text-[11px]">VERIFY INTEGRITY</div>
                  <div className="text-[10px] text-soc-500 mt-0.5">Tamper Check</div>
                </div>
              </button>
            </div>
          </Card>

          {/* Visual Breakdown Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* Column 1: Findings Distribution */}
            <Card title="Security Findings Summary" className="border-soc-800">
              <div className="space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between text-soc-300">
                  <span>Total Documented Findings:</span>
                  <span className="font-bold text-white">{currentReport.findings.length}</span>
                </div>
                <div className="space-y-2">
                  {currentReport.findings.slice(0, 4).map((f) => (
                    <div
                      key={f.finding_id}
                      className="p-2.5 bg-soc-950 rounded border border-soc-850 space-y-1"
                    >
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-bold text-blue-400">{f.finding_id}</span>
                        <span
                          className={`font-bold ${
                            f.severity === 'CRITICAL'
                              ? 'text-red-400'
                              : f.severity === 'HIGH'
                              ? 'text-orange-400'
                              : 'text-amber-400'
                          }`}
                        >
                          {f.severity}
                        </span>
                      </div>
                      <div className="text-white text-xs font-semibold">{f.title}</div>
                      <div className="text-[10px] text-soc-400">Ref: {f.evidence_reference}</div>
                    </div>
                  ))}
                </div>
              </div>
            </Card>

            {/* Column 2: Prescribed Response Plan */}
            <Card title="Prescribed Mitigations & Recommendations" className="border-soc-800">
              <div className="space-y-3 font-mono text-xs">
                {currentReport.recommendations.map((rec) => (
                  <div
                    key={rec.recommendation_id}
                    className="p-2.5 bg-soc-950 rounded border border-soc-850 space-y-1"
                  >
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="font-bold text-emerald-400">{rec.priority}</span>
                      <span className="text-soc-500 text-[10px]">{rec.category}</span>
                    </div>
                    <div className="font-semibold text-white text-xs">{rec.title}</div>
                    <div className="text-[11px] text-soc-300 font-sans">{rec.action}</div>
                  </div>
                ))}
              </div>
            </Card>

            {/* Column 3: Evidence Manifest & Cryptographic Hashes */}
            <Card title="Cryptographic Package Manifest" className="border-soc-800">
              <div className="space-y-2.5 font-mono text-xs">
                {manifest ? (
                  <>
                    <div className="text-[11px] text-soc-400">
                      Package ID: <span className="text-blue-400 font-bold">{manifest.package_id}</span>
                    </div>
                    <div className="space-y-1.5">
                      {Object.entries(manifest.file_sha256).map(([filename, hash]) => (
                        <div
                          key={filename}
                          className="p-2 bg-soc-950 rounded border border-soc-850 text-[11px] flex flex-col gap-0.5"
                        >
                          <div className="font-bold text-white flex items-center justify-between">
                            <span>{filename}</span>
                            <span className="text-[10px] text-cyan-400 font-normal">SHA-256</span>
                          </div>
                          <div className="text-soc-400 truncate text-[10px]">{hash}</div>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <p className="text-soc-500 text-xs">Manifest pre-generation pending.</p>
                )}
              </div>
            </Card>
          </div>
        </div>
      ) : null}
    </div>
  );
};
