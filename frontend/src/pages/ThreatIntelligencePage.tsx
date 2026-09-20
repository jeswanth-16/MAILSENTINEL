import React, { useState } from 'react';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { 
  Radar, 
  Search, 
  Globe, 
  Server, 
  Link as LinkIcon, 
  Mail,
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Info, 
  Database,
  CheckCircle2,
  XCircle,
  Clock,
  Network
} from 'lucide-react';
import { 
  lookupIP, 
  lookupDomain, 
  lookupURL,
  lookupEmail,
  correlateIndicators,
  getInvestigationCorrelation
} from '../services/intelligenceService';
import { 
  IPIntelligenceResult, 
  DomainIntelligenceResult, 
  URLIntelligenceResult,
  EmailAddressIntelligenceResult,
  IndicatorCorrelationResult,
  EmailRole,
  ReputationStatus,
  LookupStatus
} from '../types/intelligence';

type LookupType = 'ip' | 'domain' | 'url' | 'email' | 'correlation';

export const ThreatIntelligencePage: React.FC = () => {
  const [lookupType, setLookupType] = useState<LookupType>('ip');
  const [query, setQuery] = useState('185.220.101.5');
  const [emailRole, setEmailRole] = useState<EmailRole>('SENDER');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [ipResult, setIpResult] = useState<IPIntelligenceResult | null>(null);
  const [domainResult, setDomainResult] = useState<DomainIntelligenceResult | null>(null);
  const [urlResult, setUrlResult] = useState<URLIntelligenceResult | null>(null);
  const [emailResult, setEmailResult] = useState<EmailAddressIntelligenceResult | null>(null);
  const [correlationResult, setCorrelationResult] = useState<IndicatorCorrelationResult | null>(null);

  // Correlation form state
  const [corrInvId, setCorrInvId] = useState('INV-2026-00001');
  const [corrEmails, setCorrEmails] = useState('support@paypa1-security.com, attacker@mailinator.com');
  const [corrDomains, setCorrDomains] = useState('paypa1-security.com, mailinator.com');
  const [corrUrls, setCorrUrls] = useState('http://185.220.101.5/auth/login.php');
  const [corrIps, setCorrIps] = useState('185.220.101.5');

  const handleLookup = async (type: LookupType, value: string) => {
    if (!value.trim() && type !== 'correlation') return;
    setLoading(true);
    setError(null);

    try {
      if (type === 'ip') {
        const res = await lookupIP(value.trim());
        setIpResult(res);
        setDomainResult(null);
        setUrlResult(null);
        setEmailResult(null);
        setCorrelationResult(null);
      } else if (type === 'domain') {
        const res = await lookupDomain(value.trim());
        setDomainResult(res);
        setIpResult(null);
        setUrlResult(null);
        setEmailResult(null);
        setCorrelationResult(null);
      } else if (type === 'url') {
        const res = await lookupURL(value.trim());
        setUrlResult(res);
        setIpResult(null);
        setDomainResult(null);
        setEmailResult(null);
        setCorrelationResult(null);
      } else if (type === 'email') {
        const res = await lookupEmail(value.trim(), emailRole);
        setEmailResult(res);
        setIpResult(null);
        setDomainResult(null);
        setUrlResult(null);
        setCorrelationResult(null);
      } else if (type === 'correlation') {
        let res: IndicatorCorrelationResult;
        if (corrInvId.trim()) {
          try {
            res = await getInvestigationCorrelation(corrInvId.trim());
          } catch {
            // fallback to ad-hoc correlation
            res = await correlateIndicators({
              investigation_id: corrInvId.trim(),
              emails: corrEmails.split(',').map(s => s.trim()).filter(Boolean),
              domains: corrDomains.split(',').map(s => s.trim()).filter(Boolean),
              urls: corrUrls.split(',').map(s => s.trim()).filter(Boolean),
              ips: corrIps.split(',').map(s => s.trim()).filter(Boolean),
            });
          }
        } else {
          res = await correlateIndicators({
            emails: corrEmails.split(',').map(s => s.trim()).filter(Boolean),
            domains: corrDomains.split(',').map(s => s.trim()).filter(Boolean),
            urls: corrUrls.split(',').map(s => s.trim()).filter(Boolean),
            ips: corrIps.split(',').map(s => s.trim()).filter(Boolean),
          });
        }
        setCorrelationResult(res);
        setIpResult(null);
        setDomainResult(null);
        setUrlResult(null);
        setEmailResult(null);
      }
    } catch (err: any) {
      setError(err.message || 'Lookup failed.');
    } finally {
      setLoading(false);
    }
  };

  const getReputationBadge = (rep: ReputationStatus) => {
    switch (rep) {
      case 'KNOWN_MALICIOUS':
        return <Badge variant="severity" severity="CRITICAL">KNOWN MALICIOUS</Badge>;
      case 'SUSPICIOUS':
        return <Badge variant="severity" severity="HIGH">SUSPICIOUS</Badge>;
      case 'CLEAN':
        return <Badge variant="severity" severity="CLEAN">CLEAN</Badge>;
      case 'NOT_AVAILABLE':
        return <Badge variant="severity" severity="MEDIUM">N/A (OFFLINE)</Badge>;
      default:
        return <Badge variant="severity" severity="LOW">UNKNOWN</Badge>;
    }
  };

  const getStatusBadge = (status: LookupStatus, attribution?: string | null, cached?: boolean) => {
    if (attribution === 'REAL-TIME' || (!cached && status === 'SUCCESS' && attribution === 'REAL-TIME')) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-emerald-950/90 border border-emerald-600/70 text-emerald-400 text-xs font-mono font-bold tracking-wide">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          REAL-TIME
        </span>
      );
    }
    if (attribution === 'CACHED' || cached) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-cyan-950/90 border border-cyan-600/70 text-cyan-400 text-xs font-mono font-bold tracking-wide">
          <Database className="w-3 h-3" />
          CACHED
        </span>
      );
    }
    if (attribution === 'OFFLINE FALLBACK') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-amber-950/90 border border-amber-600/70 text-amber-400 text-xs font-mono font-bold tracking-wide">
          <ShieldAlert className="w-3 h-3" />
          OFFLINE FALLBACK
        </span>
      );
    }
    if (attribution === 'LOCAL ANALYSIS') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-blue-950/90 border border-blue-600/70 text-blue-400 text-xs font-mono font-bold tracking-wide">
          <ShieldCheck className="w-3 h-3" />
          LOCAL ANALYSIS
        </span>
      );
    }
    switch (status) {
      case 'SUCCESS':
        return <span className="inline-flex items-center gap-1 text-emerald-400 text-xs font-mono"><CheckCircle2 className="w-3.5 h-3.5" /> RESOLVED</span>;
      case 'PRIVATE_IP_SKIPPED':
        return <span className="inline-flex items-center gap-1 text-blue-400 text-xs font-mono"><Info className="w-3.5 h-3.5" /> RFC PRIVATE / SKIPPED</span>;
      case 'NOT_AVAILABLE':
        return <span className="inline-flex items-center gap-1 text-soc-400 text-xs font-mono"><Clock className="w-3.5 h-3.5" /> NOT AVAILABLE (OFFLINE)</span>;
      default:
        return <span className="inline-flex items-center gap-1 text-threat-critical text-xs font-mono"><XCircle className="w-3.5 h-3.5" /> {status}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <Radar className="w-5 h-5 text-blue-400" />
            <span>THREAT_INTELLIGENCE_ENGINE</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Cross-Entity Intelligence (Email Identity, Domain Structural/DNS, URL Decomposition, IP Geolocation) & Correlation.
          </p>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        <Card className="bg-soc-900 border-soc-800 p-3">
          <div className="text-xs font-mono text-soc-400 uppercase flex items-center justify-between">
            <span>Email Analyzer</span>
            <Mail className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-sm font-bold text-soc-100 mt-1">RFC 5322 & Syntax</div>
          <div className="text-[11px] text-soc-500 font-mono mt-1">Disposable & free mail check</div>
        </Card>
        <Card className="bg-soc-900 border-soc-800 p-3">
          <div className="text-xs font-mono text-soc-400 uppercase flex items-center justify-between">
            <span>Domain Analyzer</span>
            <Globe className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-sm font-bold text-soc-100 mt-1">Punycode & Registrable</div>
          <div className="text-[11px] text-soc-500 font-mono mt-1">IDNA, internal TLDs & lookalikes</div>
        </Card>
        <Card className="bg-soc-900 border-soc-800 p-3">
          <div className="text-xs font-mono text-soc-400 uppercase flex items-center justify-between">
            <span>URL Inspector</span>
            <LinkIcon className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-sm font-bold text-soc-100 mt-1">IP Host & Schemes</div>
          <div className="text-[11px] text-soc-500 font-mono mt-1">Port, query & redirect triage</div>
        </Card>
        <Card className="bg-soc-900 border-soc-800 p-3">
          <div className="text-xs font-mono text-soc-400 uppercase flex items-center justify-between">
            <span>RFC Filter</span>
            <ShieldCheck className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-sm font-bold text-soc-100 mt-1">RFC 1918 / 5737</div>
          <div className="text-[11px] text-soc-500 font-mono mt-1">Private & doc IPs strictly isolated</div>
        </Card>
        <Card className="bg-soc-900 border-soc-800 p-3">
          <div className="text-xs font-mono text-soc-400 uppercase flex items-center justify-between">
            <span>Correlation</span>
            <Network className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-sm font-bold text-soc-100 mt-1">Multi-Entity Graph</div>
          <div className="text-[11px] text-soc-500 font-mono mt-1">Cross-indicator threat signals</div>
        </Card>
      </div>

      {/* Entity Query Console */}
      <Card title="Threat Intelligence & Correlation Console">
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row gap-2">
            <div className="inline-flex rounded bg-soc-950 p-1 border border-soc-800 self-start flex-wrap">
              <button
                type="button"
                onClick={() => { setLookupType('ip'); setQuery('185.220.101.5'); }}
                className={`px-3 py-1.5 text-xs font-mono rounded flex items-center gap-1.5 transition-colors ${
                  lookupType === 'ip' ? 'bg-blue-600 text-white font-semibold' : 'text-soc-400 hover:text-soc-200'
                }`}
              >
                <Server className="w-3.5 h-3.5" />
                <span>IP Address</span>
              </button>
              <button
                type="button"
                onClick={() => { setLookupType('domain'); setQuery('paypa1-security.com'); }}
                className={`px-3 py-1.5 text-xs font-mono rounded flex items-center gap-1.5 transition-colors ${
                  lookupType === 'domain' ? 'bg-blue-600 text-white font-semibold' : 'text-soc-400 hover:text-soc-200'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>Domain</span>
              </button>
              <button
                type="button"
                onClick={() => { setLookupType('url'); setQuery('http://185.220.101.5/auth/login.php'); }}
                className={`px-3 py-1.5 text-xs font-mono rounded flex items-center gap-1.5 transition-colors ${
                  lookupType === 'url' ? 'bg-blue-600 text-white font-semibold' : 'text-soc-400 hover:text-soc-200'
                }`}
              >
                <LinkIcon className="w-3.5 h-3.5" />
                <span>URL</span>
              </button>
              <button
                type="button"
                onClick={() => { setLookupType('email'); setQuery('support@paypa1-security.com'); }}
                className={`px-3 py-1.5 text-xs font-mono rounded flex items-center gap-1.5 transition-colors ${
                  lookupType === 'email' ? 'bg-blue-600 text-white font-semibold' : 'text-soc-400 hover:text-soc-200'
                }`}
              >
                <Mail className="w-3.5 h-3.5" />
                <span>Email Address</span>
              </button>
              <button
                type="button"
                onClick={() => { setLookupType('correlation'); }}
                className={`px-3 py-1.5 text-xs font-mono rounded flex items-center gap-1.5 transition-colors ${
                  lookupType === 'correlation' ? 'bg-cyan-600 text-white font-semibold' : 'text-soc-400 hover:text-soc-200'
                }`}
              >
                <Network className="w-3.5 h-3.5" />
                <span>Multi-Entity Correlation</span>
              </button>
            </div>

            {lookupType !== 'correlation' ? (
              <div className="flex-1 flex flex-col sm:flex-row gap-2">
                {lookupType === 'email' && (
                  <select
                    value={emailRole}
                    onChange={(e) => setEmailRole(e.target.value as EmailRole)}
                    className="bg-soc-950 border border-soc-700 rounded px-2.5 py-2 text-xs font-mono text-soc-200 focus:outline-none focus:border-blue-500"
                  >
                    <option value="SENDER">Role: Sender (From)</option>
                    <option value="REPLY_TO">Role: Reply-To</option>
                    <option value="RETURN_PATH">Role: Return-Path</option>
                    <option value="RECIPIENT">Role: Recipient</option>
                  </select>
                )}
                <div className="relative flex-1">
                  <Search className="w-4 h-4 absolute left-3 top-2.5 text-soc-500" />
                  <input
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleLookup(lookupType, query)}
                    placeholder={`Enter ${lookupType.toUpperCase()} target...`}
                    className="w-full bg-soc-950 border border-soc-700 rounded px-3 py-2 pl-9 text-xs font-mono text-soc-100 placeholder-soc-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => handleLookup(lookupType, query)}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono font-semibold rounded transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5"
                >
                  {loading ? 'ANALYZING...' : 'QUERY'}
                </button>
              </div>
            ) : (
              <div className="flex-1 flex gap-2">
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => handleLookup('correlation', '')}
                  className="px-6 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold rounded transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5"
                >
                  {loading ? 'CORRELATING...' : 'EXECUTE CORRELATION'}
                </button>
              </div>
            )}
          </div>

          {/* Correlation multi-input form if correlation mode */}
          {lookupType === 'correlation' && (
            <div className="bg-soc-950/80 p-3 rounded border border-soc-800 space-y-3 font-mono text-xs">
              <div className="text-soc-300 font-semibold flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                <span>Correlation Parameters (Investigation ID or Custom Indicator Entities)</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] text-soc-400 block mb-1">Target Investigation ID:</label>
                  <input
                    type="text"
                    value={corrInvId}
                    onChange={(e) => setCorrInvId(e.target.value)}
                    placeholder="e.g. INV-2026-00001"
                    className="w-full bg-soc-900 border border-soc-700 rounded px-2.5 py-1.5 text-xs text-soc-100"
                  />
                </div>
                <div>
                  <label className="text-[11px] text-soc-400 block mb-1">Email Addresses (comma separated):</label>
                  <input
                    type="text"
                    value={corrEmails}
                    onChange={(e) => setCorrEmails(e.target.value)}
                    placeholder="support@paypa1-security.com, attacker@mailinator.com"
                    className="w-full bg-soc-900 border border-soc-700 rounded px-2.5 py-1.5 text-xs text-soc-100"
                  />
                </div>
                <div>
                  <label className="text-[11px] text-soc-400 block mb-1">Domain Names (comma separated):</label>
                  <input
                    type="text"
                    value={corrDomains}
                    onChange={(e) => setCorrDomains(e.target.value)}
                    placeholder="paypa1-security.com, mailinator.com"
                    className="w-full bg-soc-900 border border-soc-700 rounded px-2.5 py-1.5 text-xs text-soc-100"
                  />
                </div>
                <div>
                  <label className="text-[11px] text-soc-400 block mb-1">URLs (comma separated):</label>
                  <input
                    type="text"
                    value={corrUrls}
                    onChange={(e) => setCorrUrls(e.target.value)}
                    placeholder="http://185.220.101.5/auth/login.php"
                    className="w-full bg-soc-900 border border-soc-700 rounded px-2.5 py-1.5 text-xs text-soc-100"
                  />
                </div>
                <div>
                  <label className="text-[11px] text-soc-400 block mb-1">IP Addresses (comma separated):</label>
                  <input
                    type="text"
                    value={corrIps}
                    onChange={(e) => setCorrIps(e.target.value)}
                    placeholder="185.220.101.5, 10.0.0.1"
                    className="w-full bg-soc-900 border border-soc-700 rounded px-2.5 py-1.5 text-xs text-soc-100"
                  />
                </div>
              </div>
            </div>
          )}

          {/* Preset Quick Test Fixtures */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] font-mono text-soc-400">
            <span className="text-soc-500">Quick Test Targets:</span>
            <button
              type="button"
              onClick={() => { setLookupType('ip'); setQuery('185.220.101.5'); handleLookup('ip', '185.220.101.5'); }}
              className="px-2 py-0.5 rounded bg-soc-950 border border-soc-800 hover:border-soc-700 text-soc-300"
            >
              Public Relay (185.220.101.5)
            </button>
            <button
              type="button"
              onClick={() => { setLookupType('domain'); setQuery('paypa1-security.com'); handleLookup('domain', 'paypa1-security.com'); }}
              className="px-2 py-0.5 rounded bg-soc-950 border border-soc-800 hover:border-soc-700 text-soc-300"
            >
              Lookalike (paypa1-security.com)
            </button>
            <button
              type="button"
              onClick={() => { setLookupType('email'); setQuery('attacker@mailinator.com'); handleLookup('email', 'attacker@mailinator.com'); }}
              className="px-2 py-0.5 rounded bg-soc-950 border border-soc-800 hover:border-soc-700 text-soc-300"
            >
              Disposable Email (attacker@mailinator.com)
            </button>
            <button
              type="button"
              onClick={() => { setLookupType('email'); setQuery('Security Desk <support@paypa1-security.com>'); handleLookup('email', 'Security Desk <support@paypa1-security.com>'); }}
              className="px-2 py-0.5 rounded bg-soc-950 border border-soc-800 hover:border-soc-700 text-soc-300"
            >
              Lookalike Sender (support@paypa1-security.com)
            </button>
            <button
              type="button"
              onClick={() => { setLookupType('correlation'); setCorrInvId('INV-2026-00001'); handleLookup('correlation', ''); }}
              className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 hover:border-cyan-700 text-cyan-300"
            >
              Correlate INV-2026-00001
            </button>
          </div>

          {error && (
            <div className="p-3 bg-red-950/40 border border-red-800 text-red-300 text-xs font-mono rounded flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>
      </Card>

      {/* IP Intelligence Result Card */}
      {ipResult && (
        <Card title={`IP Intelligence: ${ipResult.ip}`}>
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-soc-800">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-soc-400">Entity:</span>
                <span className="text-xs font-mono font-bold text-soc-100">{ipResult.entity_id}</span>
                <span className="px-2 py-0.5 bg-soc-950 border border-soc-800 text-[11px] font-mono text-soc-300 rounded">
                  Category: {ipResult.category}
                </span>
              </div>
              <div className="flex items-center gap-2">
                {getStatusBadge(ipResult.status, ipResult.attribution, ipResult.cached)}
                {getReputationBadge(ipResult.reputation)}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Location & Country</div>
                <div className="text-soc-100 font-bold mt-1">
                  {ipResult.country ? `${ipResult.city ? `${ipResult.city}, ` : ''}${ipResult.country}` : 'Not Available (Offline)'}
                </div>
                <div className="text-soc-400 text-[11px] mt-0.5">Code: {ipResult.country_code || 'N/A'}</div>
              </div>

              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Network / ASN</div>
                <div className="text-soc-100 font-bold mt-1 truncate">{ipResult.asn || 'AS Unknown'}</div>
                <div className="text-soc-400 text-[11px] mt-0.5 truncate">{ipResult.organization || ipResult.isp || 'N/A'}</div>
              </div>

              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Routability & Timezone</div>
                <div className="text-soc-100 font-bold mt-1">
                  {ipResult.is_routable ? 'Public Routable' : 'Non-Routable / Isolated'}
                </div>
                <div className="text-soc-400 text-[11px] mt-0.5 truncate">TZ: {ipResult.timezone || 'UTC'}</div>
              </div>

              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Source & Attribution</div>
                <div className="text-soc-100 font-bold mt-1 truncate">{ipResult.source}</div>
                <div className="text-soc-400 text-[11px] mt-0.5 truncate">{ipResult.status_message || 'OK'}</div>
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Domain Intelligence Result Card */}
      {domainResult && (
        <Card title={`Domain Intelligence: ${domainResult.domain}`}>
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-soc-800">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-soc-400">Normalized:</span>
                <span className="text-xs font-mono font-bold text-soc-100">{domainResult.normalized_domain}</span>
                {domainResult.registrable_domain && (
                  <span className="px-2 py-0.5 bg-soc-950 border border-soc-800 text-[11px] font-mono text-cyan-300 rounded">
                    Base: {domainResult.registrable_domain}
                  </span>
                )}
                {domainResult.is_internal && (
                  <span className="px-2 py-0.5 bg-blue-950 border border-blue-800 text-[11px] font-mono text-blue-300 rounded">
                    Internal RFC TLD
                  </span>
                )}
                {domainResult.is_lookalike && (
                  <span className="px-2 py-0.5 bg-red-950 border border-red-800 text-[11px] font-mono text-red-300 rounded">
                    Brand Lookalike / Typosquat
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {getStatusBadge(domainResult.status, domainResult.attribution, domainResult.cached)}
                {getReputationBadge(domainResult.reputation)}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Structure & TLD</div>
                <div className="text-soc-100 font-bold mt-1">.{domainResult.tld || 'unknown'}</div>
                <div className="text-soc-400 text-[11px] mt-0.5">Subdomain Depth: {domainResult.subdomain_depth}</div>
              </div>

              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">A-Records / DNS</div>
                <div className="text-soc-100 font-bold mt-1 truncate">
                  {domainResult.a_records.length > 0 ? domainResult.a_records.join(', ') : 'No A-Records'}
                </div>
                <div className="text-soc-400 text-[11px] mt-0.5">DNS: {domainResult.dns_status}</div>
              </div>

              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Intelligence Source</div>
                <div className="text-soc-100 font-bold mt-1">{domainResult.source}</div>
                <div className="text-soc-400 text-[11px] mt-0.5 truncate">{domainResult.status_message}</div>
              </div>
            </div>

            {domainResult.structural_indicators.length > 0 && (
              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 space-y-2">
                <div className="text-xs font-mono text-soc-300 font-semibold flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>Structural Risk Indicators & Heuristics</span>
                </div>
                <ul className="space-y-1 text-xs font-mono text-soc-400">
                  {domainResult.structural_indicators.map((ind, i) => (
                    <li key={i} className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0" />
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* URL Intelligence Result Card */}
      {urlResult && (
        <Card title={`URL Intelligence: ${urlResult.normalized_url}`}>
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-soc-800">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-soc-400">Host Domain:</span>
                <span className="text-xs font-mono font-bold text-soc-100">{urlResult.domain}</span>
                <span className="px-2 py-0.5 bg-soc-950 border border-soc-800 text-[11px] font-mono text-soc-300 rounded">
                  {urlResult.scheme.toUpperCase()}
                </span>
                {urlResult.is_ip_host && (
                  <span className="px-2 py-0.5 bg-red-950 border border-red-800 text-[11px] font-mono text-red-300 rounded">
                    Direct IP Host
                  </span>
                )}
                {urlResult.has_credential_path && (
                  <span className="px-2 py-0.5 bg-amber-950 border border-amber-800 text-[11px] font-mono text-amber-300 rounded">
                    Credential Path
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {getStatusBadge(urlResult.status, urlResult.attribution, urlResult.cached)}
                {getReputationBadge(urlResult.reputation)}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Path & Routing</div>
                <div className="text-soc-100 font-bold mt-1 truncate">{urlResult.path || '/'}</div>
                <div className="text-soc-400 text-[11px] mt-0.5">Port: {urlResult.port || 'Default'}</div>
              </div>

              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Query Parameters</div>
                <div className="text-soc-100 font-bold mt-1 truncate">{urlResult.query || 'None'}</div>
                <div className="text-soc-400 text-[11px] mt-0.5">Punycode: {urlResult.is_punycode ? 'Yes' : 'No'}</div>
              </div>

              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Intelligence Source</div>
                <div className="text-soc-100 font-bold mt-1">{urlResult.source}</div>
                <div className="text-soc-400 text-[11px] mt-0.5 truncate">{urlResult.status_message}</div>
              </div>
            </div>

            {urlResult.structural_indicators.length > 0 && (
              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 space-y-2">
                <div className="text-xs font-mono text-soc-300 font-semibold flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-threat-critical" />
                  <span>URL Structural Risk Indicators</span>
                </div>
                <ul className="space-y-1 text-xs font-mono text-soc-400">
                  {urlResult.structural_indicators.map((ind, i) => (
                    <li key={i} className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-threat-critical shrink-0" />
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Email Address Intelligence Result Card */}
      {emailResult && (
        <Card title={`Email Intelligence: ${emailResult.normalized_email}`}>
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-soc-800">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-mono text-soc-400">Entity:</span>
                <span className="text-xs font-mono font-bold text-soc-100">{emailResult.entity_id}</span>
                <span className="px-2 py-0.5 bg-soc-950 border border-soc-800 text-[11px] font-mono text-soc-300 rounded">
                  Role: {emailResult.role}
                </span>
                {emailResult.is_disposable_domain && (
                  <span className="px-2 py-0.5 bg-red-950 border border-red-800 text-[11px] font-mono text-red-300 rounded font-bold">
                    DISPOSABLE PROVIDER
                  </span>
                )}
                {emailResult.is_free_provider && (
                  <span className="px-2 py-0.5 bg-blue-950 border border-blue-800 text-[11px] font-mono text-blue-300 rounded">
                    Free Consumer Provider
                  </span>
                )}
                {emailResult.is_lookalike_domain && (
                  <span className="px-2 py-0.5 bg-purple-950 border border-purple-800 text-[11px] font-mono text-purple-300 rounded font-bold">
                    Lookalike Brand Domain
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {getStatusBadge(emailResult.status, emailResult.attribution, emailResult.cached)}
                {getReputationBadge(emailResult.reputation)}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Local Part</div>
                <div className="text-soc-100 font-bold mt-1 truncate">{emailResult.local_part}</div>
                <div className="text-soc-400 text-[11px] mt-0.5">Syntax: {emailResult.is_valid_syntax ? 'RFC 5322 Valid' : 'Malformed'}</div>
              </div>

              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Domain Host</div>
                <div className="text-soc-100 font-bold mt-1 truncate">@{emailResult.domain}</div>
                <div className="text-soc-400 text-[11px] mt-0.5">
                  Type: {emailResult.is_disposable_domain ? 'Temporary' : (emailResult.is_free_provider ? 'Public Mail' : 'Corporate/Custom')}
                </div>
              </div>

              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Message Context Role</div>
                <div className="text-soc-100 font-bold mt-1">{emailResult.role}</div>
                <div className="text-soc-400 text-[11px] mt-0.5 truncate">Attribution: {emailResult.attribution || 'LOCAL'}</div>
              </div>

              <div className="bg-soc-950/60 p-3 rounded border border-soc-800 font-mono text-xs">
                <div className="text-soc-500 uppercase text-[10px]">Analysis Message</div>
                <div className="text-soc-100 font-bold mt-1 truncate">{emailResult.status_message || 'OK'}</div>
                <div className="text-soc-400 text-[11px] mt-0.5">Source: {emailResult.source}</div>
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Multi-Entity Indicator Correlation Result Panel */}
      {correlationResult && (
        <Card title={`Indicator Correlation Graph: ${correlationResult.investigation_id}`}>
          <div className="space-y-6">
            {/* Correlation Header & Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              <div className="bg-soc-950/80 p-3 rounded border border-soc-800 font-mono text-center">
                <div className="text-[10px] uppercase text-soc-500">Indicators Analyzed</div>
                <div className="text-lg font-bold text-soc-100 mt-1">{correlationResult.summary.total_indicators}</div>
              </div>
              <div className="bg-soc-950/80 p-3 rounded border border-soc-800 font-mono text-center">
                <div className="text-[10px] uppercase text-soc-500">Graph Relationships</div>
                <div className="text-lg font-bold text-cyan-400 mt-1">{correlationResult.summary.total_relationships}</div>
              </div>
              <div className="bg-soc-950/80 p-3 rounded border border-soc-800 font-mono text-center">
                <div className="text-[10px] uppercase text-soc-500">Threat Signals</div>
                <div className="text-lg font-bold text-threat-critical mt-1">{correlationResult.summary.total_signals}</div>
              </div>
              <div className="bg-soc-950/80 p-3 rounded border border-soc-800 font-mono text-center">
                <div className="text-[10px] uppercase text-soc-500">Mismatches Found</div>
                <div className="text-lg font-bold text-amber-400 mt-1">{correlationResult.summary.mismatches_detected}</div>
              </div>
              <div className="bg-soc-950/80 p-3 rounded border border-soc-800 font-mono text-center">
                <div className="text-[10px] uppercase text-soc-500">Infrastructure Overlap</div>
                <div className="text-lg font-bold text-purple-400 mt-1">{correlationResult.summary.infrastructure_overlap}</div>
              </div>
            </div>

            {/* Correlation Threat Signals Section */}
            {correlationResult.signals.length > 0 && (
              <div className="space-y-3">
                <h3 className="text-xs font-mono uppercase text-soc-300 font-bold flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-threat-critical" />
                  <span>Detected Correlation Threat Signals ({correlationResult.signals.length})</span>
                </h3>
                <div className="space-y-2">
                  {correlationResult.signals.map((sig, idx) => (
                    <div
                      key={idx}
                      className="bg-soc-950/80 border border-soc-800 rounded p-3 space-y-1.5 font-mono text-xs"
                    >
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            sig.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' :
                            sig.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                            'bg-blue-950 text-blue-300 border border-blue-800'
                          }`}>
                            {sig.severity}
                          </span>
                          <span className="font-bold text-soc-100">{sig.title}</span>
                          <span className="text-[10px] text-soc-500">[{sig.signal_id}]</span>
                        </div>
                        <span className="text-soc-400 text-[11px]">Weight Contribution: +{sig.weight} pts</span>
                      </div>
                      <p className="text-soc-300 text-xs">{sig.description}</p>
                      {sig.entities_involved.length > 0 && (
                        <div className="flex items-center gap-1.5 flex-wrap pt-1">
                          <span className="text-[10px] text-soc-500">Entities Involved:</span>
                          {sig.entities_involved.map((ent, eIdx) => (
                            <span key={eIdx} className="px-1.5 py-0.5 rounded bg-soc-900 border border-soc-800 text-[10px] text-soc-300">
                              {ent}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Evidence Relationships Table */}
            {correlationResult.relationships.length > 0 && (
              <div className="space-y-3">
                <h3 className="text-xs font-mono uppercase text-soc-300 font-bold flex items-center gap-2">
                  <Network className="w-4 h-4 text-cyan-400" />
                  <span>Structural Indicator Evidence Linkages ({correlationResult.relationships.length})</span>
                </h3>
                <div className="overflow-x-auto border border-soc-800 rounded">
                  <table className="w-full font-mono text-xs text-left">
                    <thead className="bg-soc-950 text-soc-400 text-[10px] uppercase border-b border-soc-800">
                      <tr>
                        <th className="px-3 py-2">Source Entity</th>
                        <th className="px-3 py-2">Relationship Link</th>
                        <th className="px-3 py-2">Target Entity</th>
                        <th className="px-3 py-2">Confidence</th>
                        <th className="px-3 py-2">Evidentiary Link / Reference</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-soc-800 bg-soc-900/50">
                      {correlationResult.relationships.map((rel, rIdx) => (
                        <tr key={rIdx} className="hover:bg-soc-800/40 transition-colors">
                          <td className="px-3 py-2 text-soc-200">
                            <span className="text-[10px] text-soc-500 block">[{rel.source_type}]</span>
                            <span className="truncate max-w-[200px] block" title={rel.source}>{rel.source}</span>
                          </td>
                          <td className="px-3 py-2">
                            <span className="px-2 py-0.5 rounded bg-soc-950 border border-cyan-800/60 text-cyan-300 text-[10px] font-bold">
                              {rel.relationship}
                            </span>
                          </td>
                          <td className="px-3 py-2 text-soc-200">
                            <span className="text-[10px] text-soc-500 block">[{rel.target_type}]</span>
                            <span className="truncate max-w-[200px] block" title={rel.target}>{rel.target}</span>
                          </td>
                          <td className="px-3 py-2 text-soc-300">
                            {(rel.confidence * 100).toFixed(0)}%
                          </td>
                          <td className="px-3 py-2 text-soc-400 text-[11px]">
                            {rel.evidence}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
};
