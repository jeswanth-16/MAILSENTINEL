import React, { useEffect, useState } from 'react';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { 
  Link2, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  Copy, 
  Check, 
  RefreshCw, 
  Clock, 
  Lock
} from 'lucide-react';
import { 
  createEvidencePackage,
  anchorEvidence,
  verifyEvidence,
  simulateTamper,
  resetTamper,
  getEvidenceRecord,
  getBlockchainLedger,
  getCustodyChain
} from '../services/blockchainService';
import { 
  BlockchainAnchorRecord, 
  CustodyEvent, 
  EvidencePackage, 
  VerificationResult 
} from '../types/blockchain';
import { ThreatSeverity } from '../types/investigation';

export const BlockchainVerificationPage: React.FC = () => {
  const [investigationId, setInvestigationId] = useState<string>('INV-2026-00001');
  const [packageData, setPackageData] = useState<EvidencePackage | null>(null);
  const [anchorRecord, setAnchorRecord] = useState<BlockchainAnchorRecord | null>(null);
  const [verificationResult, setVerificationResult] = useState<VerificationResult | null>(null);
  const [custodyEvents, setCustodyEvents] = useState<CustodyEvent[]>([]);
  const [ledger, setLedger] = useState<BlockchainAnchorRecord[]>([]);

  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [isTamperedActive, setIsTamperedActive] = useState<boolean>(false);


  // Load initial investigation package, anchor, and verification
  const loadInvestigationBlockchainData = async (invId: string) => {
    setError(null);
    try {
      // 1. Create / Get evidence package
      const pkg = await createEvidencePackage(invId);
      setPackageData(pkg);

      // 2. Fetch or create anchor
      let anchor = await getEvidenceRecord(pkg.evidence_id).catch(() => null);
      if (!anchor) {
        anchor = await anchorEvidence(pkg.evidence_id);
      }
      setAnchorRecord(anchor);

      // 3. Verify
      const verif = await verifyEvidence(pkg.evidence_id);
      setVerificationResult(verif);
      setIsTamperedActive(!verif.match);

      // 4. Fetch custody & ledger
      const custody = await getCustodyChain(invId).catch(() => []);
      setCustodyEvents(custody);

      const allLedger = await getBlockchainLedger().catch(() => []);
      setLedger(allLedger);
    } catch (err: any) {
      setError(err.message || 'Failed to load blockchain evidence.');
    }
  };


  useEffect(() => {
    loadInvestigationBlockchainData(investigationId);
  }, [investigationId]);

  const handleVerify = async () => {
    if (!packageData) return;
    setActionLoading(true);
    try {
      const verif = await verifyEvidence(packageData.evidence_id);
      setVerificationResult(verif);
      setIsTamperedActive(!verif.match);
      const custody = await getCustodyChain(investigationId);
      setCustodyEvents(custody);
    } catch (err: any) {
      setError(err.message || 'Verification failed.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleSimulateTamper = async () => {
    if (!packageData) return;
    setActionLoading(true);
    try {
      const tamperedPkg = await simulateTamper(packageData.evidence_id);
      setPackageData(tamperedPkg);
      const verif = await verifyEvidence(packageData.evidence_id);
      setVerificationResult(verif);
      setIsTamperedActive(true);
      const custody = await getCustodyChain(investigationId);
      setCustodyEvents(custody);
    } catch (err: any) {
      setError(err.message || 'Failed to simulate tamper.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleResetTamper = async () => {
    if (!packageData) return;
    setActionLoading(true);
    try {
      const originalPkg = await resetTamper(packageData.evidence_id);
      setPackageData(originalPkg);
      const verif = await verifyEvidence(packageData.evidence_id);
      setVerificationResult(verif);
      setIsTamperedActive(false);
      const custody = await getCustodyChain(investigationId);
      setCustodyEvents(custody);
    } catch (err: any) {
      setError(err.message || 'Failed to restore evidence.');
    } finally {
      setActionLoading(false);
    }
  };

  const copyHash = (hashStr: string) => {
    navigator.clipboard.writeText(hashStr);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <Link2 className="w-5 h-5 text-cyan-400" />
            <span>BLOCKCHAIN_EVIDENCE_INTEGRITY // PROOF_OF_EXISTENCE</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Immutable SHA-256 fingerprint anchoring and mathematical tamper verification for digital forensics.
          </p>
        </div>

        {/* Mode Indicator & Case Switcher */}
        <div className="flex items-center gap-3">
          <span className="px-2.5 py-1 rounded bg-cyan-950/80 border border-cyan-800/80 font-mono text-[11px] text-cyan-300 flex items-center gap-1.5 shadow-sm">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>DEMO BLOCKCHAIN LEDGER ONLINE</span>
          </span>

          <select
            value={investigationId}
            onChange={(e) => setInvestigationId(e.target.value)}
            className="bg-soc-950 border border-soc-700 rounded px-2.5 py-1 text-xs font-mono text-soc-100 focus:outline-none focus:border-cyan-500"
          >
            <option value="INV-2026-00001">INV-2026-00001 (Phishing Demo)</option>
            <option value="INV-2026-00004">INV-2026-00004 (Clean Demo)</option>
          </select>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-red-950/40 border border-red-800 text-red-300 text-xs font-mono rounded flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Top Evidence Summary Card */}
      <Card className="bg-soc-900 border-soc-800">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono text-xs">
          <div>
            <div className="text-soc-500 text-[10px] uppercase">Evidence Identifier</div>
            <div className="text-soc-100 font-bold mt-0.5">{packageData?.evidence_id || 'EVD-PENDING'}</div>
            <div className="text-soc-400 text-[11px] mt-0.5 truncate">Case: {investigationId}</div>
          </div>
          <div>
            <div className="text-soc-500 text-[10px] uppercase">File & Payload</div>
            <div className="text-soc-100 font-bold mt-0.5 truncate">{packageData?.file_name || 'sample_evidence.eml'}</div>
            <div className="text-soc-400 text-[11px] mt-0.5">{packageData?.file_size_bytes || 0} bytes</div>
          </div>
          <div>
            <div className="text-soc-500 text-[10px] uppercase">Forensic Threat Level</div>
            <div className="mt-0.5">
              <Badge variant="severity" severity={(packageData?.threat_summary?.severity || 'INFO') as ThreatSeverity}>
                {packageData?.threat_summary?.risk_score || 0}/100 • {packageData?.threat_summary?.severity || 'PENDING'}
              </Badge>
            </div>
            <div className="text-soc-400 text-[11px] mt-0.5 truncate">
              {packageData?.threat_summary?.classification || 'ANALYSIS_COMPLETE'}
            </div>
          </div>
          <div>
            <div className="text-soc-500 text-[10px] uppercase">Blockchain Anchor Status</div>
            <div className="text-emerald-400 font-bold mt-0.5 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{anchorRecord?.blockchain_status || 'ANCHORED'}</span>
            </div>
            <div className="text-soc-400 text-[11px] mt-0.5">Block #{anchorRecord?.block_number || 1042}</div>
          </div>
        </div>
      </Card>

      {/* Visual Hash Comparison Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* On-Chain Anchor Card */}
        <Card title="Immutable Blockchain Anchor Record">
          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 bg-soc-950 rounded border border-soc-800 space-y-1.5">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-soc-500 uppercase">On-Chain Recorded SHA-256 Digest</span>
                <span className="text-cyan-400">IMMUTABLE ANCHOR</span>
              </div>
              <div className="text-soc-100 font-bold break-all bg-soc-900/90 p-2 rounded border border-soc-800">
                {anchorRecord?.evidence_hash || 'Loading on-chain digest...'}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div className="bg-soc-950 p-2.5 rounded border border-soc-800">
                <span className="text-soc-500 block">LEDGER NETWORK:</span>
                <span className="text-soc-200 font-semibold">{anchorRecord?.network || 'MAILSENTINEL-DEMO-CHAIN'}</span>
              </div>
              <div className="bg-soc-950 p-2.5 rounded border border-soc-800">
                <span className="text-soc-500 block">BLOCK HEIGHT:</span>
                <span className="text-cyan-300 font-semibold">#{anchorRecord?.block_number || 1042}</span>
              </div>
              <div className="bg-soc-950 p-2.5 rounded border border-soc-800 col-span-2">
                <span className="text-soc-500 block">TRANSACTION HASH:</span>
                <span className="text-soc-300 break-all">{anchorRecord?.transaction_hash || '0x...'}</span>
              </div>
            </div>
          </div>
        </Card>

        {/* Current Recomputed Evidence Hash */}
        <Card title="Current Live Evidence Recomputed Hash">
          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 bg-soc-950 rounded border border-soc-800 space-y-1.5">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-soc-500 uppercase">Recomputed Canonical Digest</span>
                {isTamperedActive ? (
                  <span className="text-threat-critical font-bold">TAMPER TESTBED ACTIVE</span>
                ) : (
                  <span className="text-emerald-400">AUTHENTIC RECOMPUTATION</span>
                )}
              </div>
              <div className={`font-bold break-all p-2 rounded border ${
                isTamperedActive 
                  ? 'bg-red-950/40 border-red-800 text-red-300' 
                  : 'bg-soc-900/90 border-soc-800 text-soc-100'
              }`}>
                {packageData?.canonical_digest || 'Computing...'}
              </div>
            </div>

            {/* Verification Verdict Banner */}
            {verificationResult && (
              <div className={`p-3.5 rounded border flex items-start gap-2.5 ${
                verificationResult.match
                  ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-300'
                  : 'bg-red-950/40 border-red-800 text-red-200'
              }`}>
                {verificationResult.match ? (
                  <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <ShieldAlert className="w-5 h-5 text-threat-critical shrink-0 mt-0.5" />
                )}
                <div>
                  <div className="font-bold text-xs uppercase tracking-wider">
                    {verificationResult.match ? '✓ HASH MATCH • EVIDENCE INTEGRITY VERIFIED' : '✕ HASH MISMATCH • CRITICAL TAMPER DETECTED'}
                  </div>
                  <p className="text-[11px] mt-0.5 opacity-90 leading-relaxed">
                    {verificationResult.message}
                  </p>
                </div>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Interactive Demonstration Controls */}
      <Card title="Interactive Demonstration Control Matrix">
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            disabled={actionLoading}
            onClick={handleVerify}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-mono text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>VERIFY INTEGRITY ON-CHAIN</span>
          </button>

          <button
            type="button"
            disabled={actionLoading || isTamperedActive}
            onClick={handleSimulateTamper}
            className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded font-mono text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>SIMULATE EVIDENCE MODIFICATION (DEMO)</span>
          </button>

          {isTamperedActive && (
            <button
              type="button"
              disabled={actionLoading}
              onClick={handleResetTamper}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded font-mono text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>RESTORE AUTHENTIC EVIDENCE</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => copyHash(packageData?.canonical_digest || '')}
            className="px-3 py-2 bg-soc-950 hover:bg-soc-900 border border-soc-800 text-soc-300 rounded font-mono text-xs flex items-center gap-1.5 transition-colors"
          >
            {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedHash ? 'COPIED TO CLIPBOARD' : 'COPY CURRENT DIGEST'}</span>
          </button>
        </div>
      </Card>

      {/* Chain of Custody Timeline */}
      <Card title="Cryptographic Chain of Custody Audit Trail">
        <div className="space-y-3 font-mono text-xs">
          <div className="relative pl-6 border-l-2 border-cyan-800/80 space-y-4 my-2">
            {custodyEvents.map((evt) => (
              <div key={evt.event_id} className="relative">
                <span className="absolute -left-[31px] top-1.5 w-3 h-3 rounded-full bg-cyan-400 border-2 border-soc-950 shadow-[0_0_6px_rgba(6,182,212,0.6)]" />
                <div className="p-3 bg-soc-950 border border-soc-800/90 rounded space-y-1">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-2">
                      <Lock className="w-3.5 h-3.5 text-cyan-400" />
                      <span className="font-bold text-soc-100">{evt.title}</span>
                      <span className="px-1.5 py-0.5 rounded bg-soc-900 border border-soc-800 text-[10px] text-soc-400">
                        {evt.phase}
                      </span>
                    </div>
                    <span className="text-[11px] text-soc-500 flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(evt.timestamp).toUTCString().replace('GMT', 'UTC')}
                    </span>
                  </div>
                  <div className="text-soc-400 text-[11px] flex justify-between gap-2">
                    <span>Actor: {evt.actor}</span>
                    {evt.hash_reference && (
                      <span className="text-cyan-300 font-mono truncate max-w-[280px]">
                        Ref: {evt.hash_reference}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {/* Immutable Blockchain Ledger Table */}
      <Card title="Immutable Blockchain Ledger (Recent Anchors)">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-soc-800 text-soc-500 text-[11px] uppercase">
                <th className="py-2 px-3">Block #</th>
                <th className="py-2 px-3">Transaction Hash</th>
                <th className="py-2 px-3">Evidence ID</th>
                <th className="py-2 px-3">SHA-256 Digest</th>
                <th className="py-2 px-3">Status</th>
                <th className="py-2 px-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-800/60 text-soc-300">
              {ledger.map((rec) => (
                <tr key={rec.evidence_id} className="hover:bg-soc-950/40">
                  <td className="py-2.5 px-3 font-bold text-cyan-400">#{rec.block_number}</td>
                  <td className="py-2.5 px-3 text-soc-400 truncate max-w-[160px]">{rec.transaction_hash}</td>
                  <td className="py-2.5 px-3 font-semibold text-soc-100">{rec.evidence_id}</td>
                  <td className="py-2.5 px-3 text-soc-400 truncate max-w-[160px]">{rec.evidence_hash}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800 text-[11px] text-emerald-400 font-bold">
                      {rec.blockchain_status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-soc-500 text-[11px]">
                    {new Date(rec.anchored_at).toUTCString().replace('GMT', 'UTC')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
