import React, { useEffect, useState } from 'react';
import { Badge } from '../components/common/Badge';
import {
  InvestigationSummary,
  InvestigationReportData,
  ThreatSeverity,
} from '../types/investigation';
import {
  fetchInvestigations,
  fetchInvestigationReport,
} from '../services/investigationService';
import {
  FileText,
  Download,
  Printer,
  ShieldAlert,
  Link2,
  Clock,
  CheckCircle2,
  RefreshCw,
  Copy,
  Check,
} from 'lucide-react';

export const ReportsPage: React.FC = () => {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>('INV-2026-00001');
  const [report, setReport] = useState<InvestigationReportData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);

  useEffect(() => {
    async function loadCasesList() {
      try {
        const data = await fetchInvestigations();
        setInvestigations(data.investigations);
        if (data.investigations.length > 0 && !selectedCaseId) {
          setSelectedCaseId(data.investigations[0].id);
        }
      } catch (e) {
        console.error(e);
      }
    }
    loadCasesList();
  }, []);

  useEffect(() => {
    if (!selectedCaseId) return;
    async function loadReport() {
      try {
        setLoading(true);
        const data = await fetchInvestigationReport(selectedCaseId);
        setReport(data);
      } catch (e) {
        console.error('Failed to load report:', e);
      } finally {
        setLoading(false);
      }
    }
    loadReport();
  }, [selectedCaseId]);

  function handlePrint() {
    window.print();
  }

  function handleExportJSON() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `MAILSENTINEL-REPORT-${selectedCaseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleCopyReceipt() {
    if (!report) return;
    const receipt = `=== MAILSENTINEL BLOCKCHAIN EVIDENCE RECEIPT ===\nCASE ID: ${report.case.id}\nEVIDENCE SHA-256: ${report.case.evidence_hash}\nBLOCKCHAIN: ${report.case.blockchain_network || 'MAILSENTINEL-DEMO-CHAIN'}\nBLOCK NUMBER: #${report.case.blockchain_block || 1042}\nTX HASH: ${report.case.blockchain_tx || '0x83f9a2b1c4e720d58f310492e8ca55172b9a4c3f81e095da124376fb40192e47'}\nSTATUS: ${report.case.blockchain_status}\nTIMESTAMP: ${report.case.updated_at}\n================================================`;
    navigator.clipboard.writeText(receipt);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  }

  return (
    <div className="space-y-6 font-mono">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-400" />
            <span>INVESTIGATION_REPORTS // FORENSIC_DOSSIER</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Cryptographically signed, multi-source digital forensics reports for executive review and legal evidence archiving.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <select
            value={selectedCaseId}
            onChange={(e) => setSelectedCaseId(e.target.value)}
            className="px-3 py-1.5 bg-soc-950 border border-soc-800 rounded text-xs text-soc-200 focus:outline-none focus:border-blue-500"
          >
            {investigations.map((i) => (
              <option key={i.id} value={i.id}>
                {i.id} - {i.title.substring(0, 32)}...
              </option>
            ))}
          </select>

          <button
            onClick={handlePrint}
            className="px-3 py-1.5 rounded bg-soc-800 hover:bg-soc-700 text-soc-200 text-xs font-semibold flex items-center gap-1.5 transition-colors border border-soc-700"
          >
            <Printer className="w-3.5 h-3.5 text-soc-400" />
            <span>Print</span>
          </button>

          <button
            onClick={handleExportJSON}
            className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {loading || !report ? (
        <div className="p-16 text-center text-xs text-soc-400 bg-soc-900 border border-soc-800 rounded">
          <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-blue-400" />
          <span>Generating forensic report dossier for {selectedCaseId}...</span>
        </div>
      ) : (
        <div className="bg-soc-900 border border-soc-800 rounded-md p-6 space-y-6 shadow-xl">
          {/* Dossier Header Banner */}
          <div className="border-b border-soc-800 pb-5 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <span className="text-[10px] text-soc-500 uppercase block tracking-widest">
                  CONFIDENTIAL DIGITAL FORENSICS INCIDENT DOSSIER
                </span>
                <h2 className="text-lg font-bold text-soc-100">{report.case.title}</h2>
              </div>
              <div className="text-right">
                <span className="text-xs text-blue-400 font-bold block">{report.report_id}</span>
                <span className="text-[11px] text-soc-500">{new Date(report.exported_at).toLocaleString()}</span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 text-xs pt-2">
              <Badge variant="severity" severity={report.case.severity as ThreatSeverity}>
                RISK SCORE: {report.case.risk_score}/100 ({report.case.severity})
              </Badge>
              <Badge variant="status" status={report.case.status}>
                STATUS: {report.case.status}
              </Badge>
              <span className="text-soc-400">
                Lead Analyst: <strong className="text-soc-200">{report.case.assigned_analyst}</strong>
              </span>
              <span className="text-soc-400">
                Classification: <strong className="text-soc-200">{report.case.classification}</strong>
              </span>
            </div>
          </div>

          {/* Section 1: Executive Summary */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold text-soc-300 uppercase tracking-wide border-b border-soc-800/80 pb-1 flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5 text-threat-critical" />
              <span>1. Executive Threat Summary & Incident Findings</span>
            </h3>
            <p className="text-xs text-soc-300 leading-relaxed bg-soc-950 p-3 rounded border border-soc-800">
              {report.case.verdict_summary || report.case.description}
            </p>
          </div>

          {/* Section 2: Email Authentication & Origin Verification */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold text-soc-300 uppercase tracking-wide border-b border-soc-800/80 pb-1">
              2. Cryptographic Email Authentication & Perimeter Trace
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1.5">
                <div>
                  <span className="text-soc-500">Suspect Sender: </span>
                  <span className="text-soc-200">{report.case.sender}</span>
                </div>
                <div>
                  <span className="text-soc-500">Subject: </span>
                  <span className="text-soc-200">{report.case.subject}</span>
                </div>
                <div>
                  <span className="text-soc-500">Primary Ingestion Source: </span>
                  <span className="text-soc-300">{report.case.source}</span>
                </div>
              </div>

              <div className="p-3 bg-soc-950 border border-soc-800 rounded space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-soc-500">SPF Alignment:</span>
                  <span className="text-red-400 font-bold">FAIL (Unmatched sending IP)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-soc-500">DKIM Signature:</span>
                  <span className="text-red-400 font-bold">FAIL (Signature missing/invalid)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-soc-500">DMARC Policy:</span>
                  <span className="text-red-400 font-bold">FAIL (Policy enforcement triggered)</span>
                </div>
              </div>
            </div>
          </div>

          {/* Section 3: Recommended Defensive Containment */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold text-soc-300 uppercase tracking-wide border-b border-soc-800/80 pb-1">
              3. Recommended Defensive Remediation & Containment
            </h3>
            <div className="space-y-1.5 text-xs">
              {report.case.recommended_actions.map((act, idx) => (
                <div
                  key={idx}
                  className="p-2.5 bg-blue-950/30 border border-blue-800/50 rounded flex items-center gap-2 text-blue-200 text-xs"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-blue-400 flex-shrink-0" />
                  <span>{act}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Section 4: Blockchain Evidence Integrity Anchor */}
          <div className="space-y-2">
            <div className="flex items-center justify-between border-b border-soc-800/80 pb-1">
              <h3 className="text-xs font-bold text-soc-300 uppercase tracking-wide flex items-center gap-2">
                <Link2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>4. Immutable Blockchain Evidence Fingerprint</span>
              </h3>
              <button
                onClick={handleCopyReceipt}
                className="text-[11px] text-blue-400 hover:text-blue-300 flex items-center gap-1"
              >
                {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>Copy Receipt</span>
              </button>
            </div>

            <div className="p-3.5 bg-soc-950 border border-soc-800 rounded space-y-2 text-xs">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-soc-500">Evidence ID:</span>
                <span className="text-blue-400">{report.case.evidence_id || 'EVD-2026-00001'}</span>
              </div>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-soc-500">Canonical SHA-256 Digest:</span>
                <span className="text-soc-200 select-all truncate max-w-md">{report.case.evidence_hash}</span>
              </div>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-soc-500">Blockchain Network:</span>
                <span className="text-soc-300">{report.case.blockchain_network || 'MAILSENTINEL-DEMO-CHAIN'}</span>
              </div>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-soc-500">Block Anchor Reference:</span>
                <span className="text-emerald-400">Block #{report.case.blockchain_block || 1042}</span>
              </div>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-soc-500">Transaction Hash:</span>
                <span className="text-soc-400 select-all truncate max-w-md">
                  {report.case.blockchain_tx || '0x83f9a2b1c4e720d58f310492e8ca55172b9a4c3f81e095da124376fb40192e47'}
                </span>
              </div>
            </div>
          </div>

          {/* Section 5: Case Notes & Audit Trail */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold text-soc-300 uppercase tracking-wide border-b border-soc-800/80 pb-1 flex items-center gap-2">
              <Clock className="w-3.5 h-3.5 text-soc-400" />
              <span>5. Chronological Chain of Custody & Analyst Notes</span>
            </h3>
            <div className="space-y-2 text-xs">
              {report.case.notes.map((note) => (
                <div
                  key={note.note_id}
                  className="p-2.5 bg-soc-950 border border-soc-800 rounded space-y-1 text-xs"
                >
                  <div className="flex items-center justify-between text-[10px] text-soc-500">
                    <span>{note.author} ({note.note_type})</span>
                    <span>{new Date(note.timestamp).toLocaleString()}</span>
                  </div>
                  <p className="text-soc-300">{note.content}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
