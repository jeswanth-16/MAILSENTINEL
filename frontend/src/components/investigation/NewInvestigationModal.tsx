import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload,
  Zap,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  X,
  RefreshCw,
  Link2,
} from 'lucide-react';
import { runFullInvestigation } from '../../services/investigationService';
import { SAMPLE_PHISHING_EML_TEXT, SAMPLE_CLEAN_EML_TEXT } from '../../data/sampleEml';

interface NewInvestigationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const PIPELINE_STAGES = [
  'Evidence Ingested & SHA-256 Calculated',
  'RFC 5322 MIME & Header Structure Parsed',
  'Authentication Evaluated (SPF/DKIM/DMARC)',
  'Threat Indicators & Risk Scoring Evaluated (0-100)',
  'Observed Network Infrastructure Enriched (IP / Geo / ASN / Domain)',
  'Forensic Hop Timeline Reconstructed',
  'Attack Infrastructure & Entity Graph Generated',
  'AI SOC Analyst Assessment & MITRE ATT&CK Correlated',
  'Canonical Evidence Package Prepared & SHA-256 Fingerprinted',
  'Blockchain Evidence Anchor Initialized',
];

export const NewInvestigationModal: React.FC<NewInvestigationModalProps> = ({
  isOpen,
  onClose,
}) => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedPresetName, setSelectedPresetName] = useState<string | null>(null);
  const [analystName, setAnalystName] = useState<string>('SOC-L2-ANALYST');
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(-1);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setSelectedPresetName(null);
      setError(null);
    }
  }

  function handleSelectPreset(presetType: 'phishing' | 'clean') {
    if (presetType === 'phishing') {
      const blob = new Blob([SAMPLE_PHISHING_EML_TEXT], { type: 'message/rfc822' });
      const file = new File([blob], 'sample_phishing.eml', { type: 'message/rfc822' });
      setSelectedFile(file);
      setSelectedPresetName('Demo Scenario A: High-Risk BEC Phishing (sample_phishing.eml)');
    } else {
      const blob = new Blob([SAMPLE_CLEAN_EML_TEXT], { type: 'message/rfc822' });
      const file = new File([blob], 'valid_clean.eml', { type: 'message/rfc822' });
      setSelectedFile(file);
      setSelectedPresetName('Demo Scenario B: Clean Corporate Email (valid_clean.eml)');
    }
    setError(null);
  }

  async function handleLaunchPipeline() {
    if (!selectedFile) {
      setError('Please upload a .EML file or select a demo scenario.');
      return;
    }

    try {
      setIsRunning(true);
      setError(null);
      setCurrentStepIndex(0);

      // Smooth step simulation while actual backend request runs
      const stepTimer = setInterval(() => {
        setCurrentStepIndex((prev) => {
          if (prev < PIPELINE_STAGES.length - 2) return prev + 1;
          return prev;
        });
      }, 250);

      const res = await runFullInvestigation(selectedFile, analystName.trim() || 'SOC-L2-ANALYST');
      clearInterval(stepTimer);
      setCurrentStepIndex(PIPELINE_STAGES.length - 1);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Automated triage pipeline failed.');
      setCurrentStepIndex(-1);
    } finally {
      setIsRunning(false);
    }
  }

  function handleNavigateToWorkbench() {
    if (result && result.investigation) {
      onClose();
      navigate(`/investigations/${result.investigation.id}`);
    }
  }

  function handleReset() {
    setSelectedFile(null);
    setSelectedPresetName(null);
    setCurrentStepIndex(-1);
    setResult(null);
    setError(null);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-soc-900 border border-soc-700 rounded-lg max-w-2xl w-full shadow-2xl font-mono text-xs overflow-hidden">
        {/* Header */}
        <div className="p-4 bg-soc-950 border-b border-soc-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-blue-400" />
            <span className="font-bold text-soc-100 text-sm">
              NEW INVESTIGATION // AUTOMATED_SOC_TRIAGE
            </span>
          </div>
          <button
            onClick={onClose}
            className="text-soc-400 hover:text-soc-100 transition-colors p-1"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-5 max-h-[80vh] overflow-y-auto">
          {/* Error Banner */}
          {error && (
            <div className="p-3 bg-red-950/60 border border-red-800 rounded flex items-center gap-2 text-red-300">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {!result ? (
            <>
              {/* Scenario Preset Selector */}
              <div className="space-y-2">
                <label className="text-[11px] text-soc-400 font-semibold uppercase block">
                  1. Select Ingestion Source or SIH Demo Scenario
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => handleSelectPreset('phishing')}
                    disabled={isRunning}
                    className={`p-3 rounded border text-left transition-colors flex flex-col justify-between ${
                      selectedPresetName?.includes('BEC')
                        ? 'bg-red-950/40 border-red-600 text-red-200'
                        : 'bg-soc-950 border-soc-800 hover:border-soc-700 text-soc-300'
                    }`}
                  >
                    <div className="flex items-center justify-between w-full">
                      <span className="font-bold text-soc-100">Scenario A: Phishing / BEC</span>
                      <ShieldAlert className="w-3.5 h-3.5 text-threat-critical" />
                    </div>
                    <p className="text-[10px] text-soc-400 mt-1">
                      Critical executive wire fraud, lookalike domain, SPF/DMARC failure & malicious attachment.
                    </p>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleSelectPreset('clean')}
                    disabled={isRunning}
                    className={`p-3 rounded border text-left transition-colors flex flex-col justify-between ${
                      selectedPresetName?.includes('Clean')
                        ? 'bg-emerald-950/40 border-emerald-600 text-emerald-200'
                        : 'bg-soc-950 border-soc-800 hover:border-soc-700 text-soc-300'
                    }`}
                  >
                    <div className="flex items-center justify-between w-full">
                      <span className="font-bold text-soc-100">Scenario B: Clean Email</span>
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    </div>
                    <p className="text-[10px] text-soc-400 mt-1">
                      Benign corporate notification with valid SPF/DKIM/DMARC authentication.
                    </p>
                  </button>
                </div>
              </div>

              {/* Custom File Upload */}
              <div className="space-y-2">
                <label className="text-[11px] text-soc-400 font-semibold uppercase block">
                  OR Upload Custom Raw Email (.EML)
                </label>
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="p-4 border-2 border-dashed border-soc-800 hover:border-blue-500 rounded bg-soc-950/50 text-center cursor-pointer transition-colors space-y-1"
                >
                  <Upload className="w-5 h-5 text-soc-400 mx-auto" />
                  <div className="text-soc-300 font-medium">
                    {selectedFile && !selectedPresetName
                      ? selectedFile.name
                      : 'Click to browse or drag & drop .EML file'}
                  </div>
                  <div className="text-[10px] text-soc-500">
                    Supports RFC 5322 MIME format (.eml, .msg, .txt)
                  </div>
                </div>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileSelect}
                  accept=".eml,.msg,.txt"
                  className="hidden"
                />
              </div>

              {/* Analyst Field */}
              <div className="space-y-1.5">
                <label className="text-[11px] text-soc-400 font-semibold uppercase block">
                  2. Assigned SOC Analyst
                </label>
                <input
                  type="text"
                  value={analystName}
                  onChange={(e) => setAnalystName(e.target.value)}
                  disabled={isRunning}
                  placeholder="e.g. SOC-L2-ANALYST"
                  className="w-full bg-soc-950 border border-soc-800 rounded px-3 py-2 text-soc-100 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Progress Checklist (When Running) */}
              {isRunning && (
                <div className="p-4 bg-soc-950 border border-soc-800 rounded space-y-2.5">
                  <div className="flex items-center justify-between text-[11px] font-bold text-blue-400 border-b border-soc-800 pb-2">
                    <span className="flex items-center gap-1.5">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      EXECUTING END-TO-END INVESTIGATION PIPELINE...
                    </span>
                    <span>{Math.min(currentStepIndex + 1, 10)} / 10</span>
                  </div>
                  <div className="space-y-1.5">
                    {PIPELINE_STAGES.map((stg, idx) => (
                      <div
                        key={idx}
                        className={`flex items-center gap-2 text-[11px] transition-colors ${
                          idx < currentStepIndex
                            ? 'text-emerald-400 font-semibold'
                            : idx === currentStepIndex
                            ? 'text-blue-300 font-bold animate-pulse'
                            : 'text-soc-600'
                        }`}
                      >
                        {idx < currentStepIndex ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                        ) : idx === currentStepIndex ? (
                          <RefreshCw className="w-3.5 h-3.5 text-blue-400 animate-spin flex-shrink-0" />
                        ) : (
                          <div className="w-3.5 h-3.5 rounded-full border border-soc-700 flex-shrink-0" />
                        )}
                        <span>{stg}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            /* Result Summary View */
            <div className="space-y-4">
              <div className="p-4 bg-emerald-950/30 border border-emerald-800/80 rounded space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>INVESTIGATION PIPELINE COMPLETED</span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-soc-900 text-soc-300 border border-soc-700">
                    {result.investigation.id}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center font-mono">
                  <div className="p-2 bg-soc-950 rounded border border-soc-800">
                    <span className="text-[10px] text-soc-500 block">RISK SCORE</span>
                    <span
                      className={`text-base font-bold ${
                        result.investigation.risk_score >= 80
                          ? 'text-threat-critical'
                          : result.investigation.risk_score >= 50
                          ? 'text-threat-high'
                          : 'text-emerald-400'
                      }`}
                    >
                      {result.investigation.risk_score} / 100
                    </span>
                  </div>

                  <div className="p-2 bg-soc-950 rounded border border-soc-800">
                    <span className="text-[10px] text-soc-500 block">SEVERITY</span>
                    <span className="text-xs font-bold text-soc-200">
                      {result.investigation.severity}
                    </span>
                  </div>

                  <div className="p-2 bg-soc-950 rounded border border-soc-800">
                    <span className="text-[10px] text-soc-500 block">AI PATTERN</span>
                    <span className="text-xs font-bold text-purple-300 truncate block">
                      {result.investigation.classification}
                    </span>
                  </div>

                  <div className="p-2 bg-soc-950 rounded border border-soc-800">
                    <span className="text-[10px] text-soc-500 block">BLOCKCHAIN</span>
                    <span className="text-xs font-bold text-cyan-300">
                      BLOCK #{result.investigation.blockchain_block || 1042}
                    </span>
                  </div>
                </div>

                <div className="space-y-1 text-[11px] text-soc-300 bg-soc-950 p-2.5 rounded border border-soc-800">
                  <div className="flex items-center gap-1 text-soc-400">
                    <Link2 className="w-3 h-3 text-cyan-400" />
                    <span>Evidence SHA-256:</span>
                  </div>
                  <div className="font-mono text-soc-200 truncate select-all">
                    {result.investigation.evidence_hash}
                  </div>
                </div>
              </div>

              {/* Completed Steps Log */}
              <div className="space-y-1 max-h-36 overflow-y-auto p-2.5 bg-soc-950 border border-soc-800 rounded">
                <span className="text-[10px] text-soc-500 font-semibold uppercase block mb-1">
                  Automated Pipeline Execution Log:
                </span>
                {result.steps_completed.map((step: string, idx: number) => (
                  <div key={idx} className="flex items-center gap-1.5 text-[10px] text-soc-300">
                    <span className="text-emerald-400">✓</span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 bg-soc-950 border-t border-soc-800 flex items-center justify-between gap-3">
          <button
            type="button"
            onClick={result ? handleReset : onClose}
            disabled={isRunning}
            className="px-3 py-1.5 rounded bg-soc-800 hover:bg-soc-700 text-soc-300 border border-soc-700 transition-colors"
          >
            {result ? 'Run Another Case' : 'Cancel'}
          </button>

          {!result ? (
            <button
              type="button"
              onClick={handleLaunchPipeline}
              disabled={isRunning || !selectedFile}
              className={`px-4 py-2 rounded font-semibold flex items-center gap-1.5 transition-colors shadow-sm ${
                isRunning || !selectedFile
                  ? 'bg-soc-800 text-soc-500 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-500 text-white'
              }`}
            >
              {isRunning ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Processing...</span>
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5 text-yellow-300" />
                  <span>Launch Investigation Pipeline</span>
                </>
              )}
            </button>
          ) : (
            <button
              type="button"
              onClick={handleNavigateToWorkbench}
              className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1.5 transition-colors shadow-md"
            >
              <span>Open Investigation Workbench</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
