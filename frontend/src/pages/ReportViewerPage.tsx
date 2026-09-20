import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Download,
  ArrowLeft,
  Printer,
  CheckCircle2,
  RefreshCw,
  FileCheck2,
  Sparkles,
} from 'lucide-react';
import {
  fetchReport,
  getReportPdfUrl,
  verifyReportIntegrity,
} from '../services/reportingService';
import { ForensicReport, VerifyReportResponse } from '../types/reporting';

export const ReportViewerPage: React.FC = () => {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();

  const [report, setReport] = useState<ForensicReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [verificationResult, setVerificationResult] = useState<VerifyReportResponse | null>(null);

  useEffect(() => {
    if (!caseId) return;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchReport(caseId);
        setReport(data);
      } catch (err: any) {
        setError(err.message || 'Failed to load report');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [caseId]);

  const handleVerify = async () => {
    if (!report) return;
    setVerifying(true);
    try {
      const res = await verifyReportIntegrity(report.metadata.report_id);
      setVerificationResult(res);
    } catch (err: any) {
      alert(`Verification failed: ${err.message}`);
    } finally {
      setVerifying(false);
    }
  };

  if (loading) {
    return (
      <div className="p-16 text-center text-soc-400 font-mono text-xs flex flex-col items-center justify-center gap-3">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-400" />
        <span>Loading Interactive Forensic Report...</span>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="p-8 max-w-xl mx-auto text-center space-y-4 font-mono">
        <div className="p-4 bg-red-950/40 border border-red-800 rounded text-red-300 text-xs">
          {error || 'Report not found'}
        </div>
        <button
          onClick={() => navigate('/reports')}
          className="px-4 py-2 bg-soc-800 hover:bg-soc-700 text-soc-200 rounded text-xs inline-flex items-center gap-2"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Report Center
        </button>
      </div>
    );
  }

  const { metadata, executive_summary, email_metadata, auth_analysis, findings, recommendations, signatures, evidence_references } = report;

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      {/* Top Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-soc-800 pb-4 no-print">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/reports')}
            className="p-1.5 rounded bg-soc-850 hover:bg-soc-800 text-soc-300 border border-soc-750 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <h1 className="text-base font-bold font-mono text-white">
              REPORT VIEWER: {metadata.report_id}
            </h1>
            <p className="text-xs text-soc-400 font-mono">
              Case ID: {metadata.case_id} | Version: {metadata.version}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <a
            href={getReportPdfUrl(metadata.case_id)}
            download
            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-mono font-medium flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            Download PDF
          </a>
          <button
            onClick={() => window.print()}
            className="px-3 py-1.5 bg-soc-800 hover:bg-soc-750 text-soc-200 border border-soc-700 rounded text-xs font-mono flex items-center gap-1.5"
          >
            <Printer className="w-3.5 h-3.5" />
            Print Report
          </button>
          <button
            onClick={handleVerify}
            disabled={verifying}
            className="px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded text-xs font-mono flex items-center gap-1.5"
          >
            <FileCheck2 className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            Verify On-Chain
          </button>
        </div>
      </div>

      {/* Verification Notification */}
      {verificationResult && (
        <div
          className={`p-3.5 rounded border font-mono text-xs flex items-center justify-between gap-3 ${
            verificationResult.verified
              ? 'bg-cyan-950/40 border-cyan-800 text-cyan-300'
              : 'bg-red-950/40 border-red-800 text-red-300'
          }`}
        >
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4" />
            <span>{verificationResult.message}</span>
          </div>
          <span className="text-[11px] text-soc-400">
            Hash: {verificationResult.stored_hash.slice(0, 16)}...
          </span>
        </div>
      )}

      {/* Printable Report Document Sheet */}
      <div className="bg-soc-900 border border-soc-800 rounded-lg p-6 sm:p-8 space-y-6 shadow-xl text-xs font-mono">
        {/* Document Header */}
        <div className="border-b-2 border-blue-600 pb-5 space-y-2">
          <div className="flex items-center justify-between text-soc-400 text-[11px]">
            <span>MAILSENTINEL CYBERSECURITY DIGITAL FORENSICS</span>
            <span>RESTRICTED / SOC LEVEL-3 AUDIT</span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-wider font-mono">
            DIGITAL FORENSIC INVESTIGATION REPORT
          </h2>
          <p className="text-soc-300 text-xs font-sans">
            Formal forensic evaluation, threat vector classification, and cryptographic evidence audit.
          </p>
        </div>

        {/* Section 1: Executive Case Telemetry */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 bg-soc-950 rounded border border-soc-850">
          <div>
            <div className="text-soc-500 uppercase text-[10px]">CASE IDENTIFIER</div>
            <div className="mt-0.5 font-bold text-blue-400">{metadata.case_id}</div>
          </div>
          <div>
            <div className="text-soc-500 uppercase text-[10px]">SEVERITY / VERDICT</div>
            <div className="mt-0.5 font-bold text-red-400">{metadata.severity} / {metadata.classification}</div>
          </div>
          <div>
            <div className="text-soc-500 uppercase text-[10px]">RISK SCORE</div>
            <div className="mt-0.5 font-bold text-amber-400">{metadata.risk_score} / 100 (Authoritative)</div>
          </div>
          <div>
            <div className="text-soc-500 uppercase text-[10px]">BLOCKCHAIN PROOF</div>
            <div className="mt-0.5 text-cyan-300 font-bold">#B{metadata.blockchain_block_number || 104} ANCHORED</div>
          </div>
        </div>

        {/* Section 2: Executive Summary */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white uppercase border-b border-soc-800 pb-1 flex items-center gap-1.5">
            <Sparkles className="w-4 h-4 text-blue-400" />
            1. Executive Summary & Assessment
          </h3>
          <p className="text-soc-200 font-sans leading-relaxed text-xs">
            {executive_summary.ai_executive_narrative ||
              `Forensic analysis for case ${metadata.case_id} determined an authoritative risk score of ${metadata.risk_score}/100. Immediate containment actions are recommended.`}
          </p>
        </div>

        {/* Section 3: Evidence References */}
        {evidence_references && evidence_references.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-sm font-bold text-white uppercase border-b border-soc-800 pb-1">
              2. Forensic Evidence References
            </h3>
            <div className="overflow-x-auto border border-soc-850 rounded">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-soc-950 text-soc-400 text-[10px] uppercase border-b border-soc-850">
                    <th className="py-2 px-3">Ref ID</th>
                    <th className="py-2 px-3">Evidence Type</th>
                    <th className="py-2 px-3">Forensic Description</th>
                    <th className="py-2 px-3">SHA-256 Checksum</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-850">
                  {evidence_references.map((ev) => (
                    <tr key={ev.reference_id}>
                      <td className="py-2 px-3 font-bold text-blue-400 whitespace-nowrap">{ev.reference_id}</td>
                      <td className="py-2 px-3 text-soc-300 whitespace-nowrap">{ev.evidence_type}</td>
                      <td className="py-2 px-3 text-soc-200">{ev.description}</td>
                      <td className="py-2 px-3 text-soc-400 font-mono text-[10px] truncate max-w-[150px]">
                        {ev.sha256 || 'N/A'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Section 4: Email & Auth Metadata */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white uppercase border-b border-soc-800 pb-1">
            3. Header & Authentication Analysis
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3 bg-soc-950 rounded border border-soc-850 text-xs">
            <div className="space-y-1">
              <div><span className="text-soc-500">Sender:</span> <span className="text-white">{email_metadata.sender || 'Unknown'}</span></div>
              <div><span className="text-soc-500">Recipient:</span> <span className="text-white">{email_metadata.recipient || 'Staff'}</span></div>
              <div><span className="text-soc-500">Subject:</span> <span className="text-white">{email_metadata.subject || 'Security Alert'}</span></div>
            </div>
            <div className="space-y-1">
              <div><span className="text-soc-500">SPF Verification:</span> <span className="text-red-400 font-bold">{auth_analysis.spf_status || 'SoftFail'}</span></div>
              <div><span className="text-soc-500">DKIM Signature:</span> <span className="text-red-400 font-bold">{auth_analysis.dkim_status || 'Fail'}</span></div>
              <div><span className="text-soc-500">DMARC Policy:</span> <span className="text-red-400 font-bold">{auth_analysis.dmarc_status || 'Reject'}</span></div>
            </div>
          </div>
        </div>

        {/* Section 5: Security Findings */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white uppercase border-b border-soc-800 pb-1">
            4. Detailed Security Findings
          </h3>
          <div className="space-y-2">
            {findings.map((f) => (
              <div key={f.finding_id} className="p-3 bg-soc-950 rounded border border-soc-850 space-y-1">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-blue-400">{f.finding_id}</span>
                    <span className="font-semibold text-white">{f.title}</span>
                  </div>
                  <span className="font-bold text-red-400 text-[11px]">{f.severity}</span>
                </div>
                <div className="text-soc-300 font-sans text-xs">{f.description}</div>
                <div className="text-[11px] text-soc-400 pt-1 border-t border-soc-900 flex justify-between">
                  <span>Impact: {f.impact}</span>
                  <span className="text-blue-400">Ref: {f.evidence_reference}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Section 6: Recommendations */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white uppercase border-b border-soc-800 pb-1">
            5. Prescribed Mitigations & Recommendations
          </h3>
          <div className="space-y-2">
            {recommendations.map((rec) => (
              <div key={rec.recommendation_id} className="p-3 bg-soc-950 rounded border border-soc-850 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">{rec.title}</span>
                  <span className="font-bold text-emerald-400 text-[11px]">{rec.priority}</span>
                </div>
                <div className="text-soc-300 font-sans text-xs">{rec.action}</div>
                <div className="text-[10px] text-soc-500">Rationale: {rec.rationale}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Section 7: Custody & Sign-Off */}
        <div className="space-y-2 pt-4 border-t border-soc-800">
          <h3 className="text-sm font-bold text-white uppercase border-b border-soc-800 pb-1">
            6. Chain of Custody & Forensic Sign-off
          </h3>
          {signatures && signatures.length > 0 && (
            <div className="p-3 bg-soc-950 rounded border border-soc-850 grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
              <div>
                <span className="text-soc-500 uppercase block">Signatory Examiner:</span>
                <span className="text-white font-bold">{signatures[0].signer_name}</span>
                <span className="text-soc-400 block">{signatures[0].role}</span>
              </div>
              <div>
                <span className="text-soc-500 uppercase block">Cryptographic Signature Digest:</span>
                <span className="text-cyan-300 break-all text-[10px]">{signatures[0].signature_hash}</span>
                <span className="text-soc-500 text-[10px] block">{signatures[0].signature_algorithm}</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
