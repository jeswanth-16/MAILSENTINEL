import React, { useEffect, useState } from 'react';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { 
  GitCommit, 
  Clock, 
  ShieldAlert, 
  Server, 
  Mail, 
  Link as LinkIcon, 
  FileText, 
  Search, 
  ArrowUpDown, 
  Copy, 
  Check, 
  ChevronDown, 
  ChevronUp, 
  AlertTriangle, 
  Info,
  Globe,
  Database,
  Hash,
  ShieldCheck
} from 'lucide-react';

import { getInvestigationTimeline } from '../services/forensicsService';
import { TimelineEvent, TimelineEventType } from '../types/forensics';
import { ThreatSeverity } from '../types/investigation';

export const TimelinePage: React.FC = () => {
  const [investigationId, setInvestigationId] = useState<string>('INV-2026-00001');
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filter & Search states
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedEventType, setSelectedEventType] = useState<string>('ALL');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Expanded events state
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    const fetchTimeline = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await getInvestigationTimeline(
          investigationId,
          sortOrder,
          selectedSeverity,
          selectedEventType
        );
        if (isMounted) {
          setEvents(res.events);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || 'Failed to load timeline.');
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchTimeline();
    return () => { isMounted = false; };
  }, [investigationId, sortOrder, selectedSeverity, selectedEventType]);

  const toggleExpand = (id: string) => {
    setExpandedEvents(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const getEventIcon = (type: TimelineEventType) => {
    switch (type) {
      case 'EMAIL_CREATED':
      case 'EMAIL_RECEIVED':
        return <Mail className="w-4 h-4 text-blue-400" />;
      case 'SMTP_RELAY':
        return <Server className="w-4 h-4 text-blue-400" />;
      case 'AUTHENTICATION_CHECK':
        return <ShieldCheck className="w-4 h-4 text-amber-400" />;
      case 'URL_DISCOVERED':
        return <LinkIcon className="w-4 h-4 text-purple-400" />;
      case 'DOMAIN_DISCOVERED':
        return <Globe className="w-4 h-4 text-indigo-400" />;
      case 'IP_DISCOVERED':
        return <Database className="w-4 h-4 text-sky-400" />;
      case 'ATTACHMENT_DISCOVERED':
        return <FileText className="w-4 h-4 text-red-400" />;
      case 'THREAT_INDICATOR':
        return <ShieldAlert className="w-4 h-4 text-threat-critical" />;
      case 'GEOLOCATION_RESOLVED':
        return <Globe className="w-4 h-4 text-emerald-400" />;
      case 'RISK_ASSESSMENT':
        return <AlertTriangle className="w-4 h-4 text-threat-high" />;
      case 'EVIDENCE_HASHED':
        return <Hash className="w-4 h-4 text-cyan-400" />;
      default:
        return <Info className="w-4 h-4 text-soc-400" />;
    }
  };

  const getDotColorClass = (severity?: string | null) => {
    const sev = (severity || 'INFO').toUpperCase();
    if (sev === 'CRITICAL') return 'bg-red-500 border-red-400 shadow-[0_0_8px_rgba(239,68,68,0.6)]';
    if (sev === 'HIGH') return 'bg-orange-500 border-orange-400 shadow-[0_0_8px_rgba(249,115,22,0.5)]';
    if (sev === 'MEDIUM') return 'bg-amber-500 border-amber-400';
    if (sev === 'CLEAN') return 'bg-emerald-500 border-emerald-400';
    return 'bg-blue-500 border-blue-400';
  };

  // Local search filter
  const filteredEvents = events.filter(e => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    return (
      e.title.toLowerCase().includes(term) ||
      e.description.toLowerCase().includes(term) ||
      (e.evidence_reference && e.evidence_reference.toLowerCase().includes(term)) ||
      (e.entity_id && e.entity_id.toLowerCase().includes(term))
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <GitCommit className="w-5 h-5 text-blue-400" />
            <span>FORENSIC_EVIDENCE_TIMELINE</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Chronological and relational reconstruction of SMTP hops, authentication events, indicators, and evidence hashes.
          </p>
        </div>

        {/* Investigation Preset Switcher */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-soc-400">Target Case:</span>
          <select
            value={investigationId}
            onChange={(e) => setInvestigationId(e.target.value)}
            className="bg-soc-950 border border-soc-700 rounded px-2.5 py-1 text-xs font-mono text-soc-100 focus:outline-none focus:border-blue-500"
          >
            <option value="INV-2026-00001">INV-2026-00001 (CEO Wire Phishing Demo)</option>
            <option value="INV-2026-00004">INV-2026-00004 (Internal Clean Email Demo)</option>
          </select>
        </div>
      </div>

      {/* Investigation Context Persistent Card */}
      <Card className="bg-soc-900 border-soc-800">
        <div className="flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
          <div className="flex items-center gap-3">
            <div>
              <div className="text-soc-500 text-[10px] uppercase">Active Investigation</div>
              <div className="text-sm font-bold text-soc-100">{investigationId}</div>
            </div>
            <div className="h-7 w-px bg-soc-800" />
            <div>
              <div className="text-soc-500 text-[10px] uppercase">Classification</div>
              <div className="text-soc-200 font-semibold">
                {investigationId === 'INV-2026-00001' ? 'BUSINESS_EMAIL_COMPROMISE' : 'BENIGN'}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div>
              <div className="text-soc-500 text-[10px] uppercase">Risk Verdict</div>
              <div className="mt-0.5">
                {investigationId === 'INV-2026-00001' ? (
                  <Badge variant="severity" severity="CRITICAL">94/100 • CRITICAL</Badge>
                ) : (
                  <Badge variant="severity" severity="CLEAN">4/100 • CLEAN</Badge>
                )}
              </div>
            </div>
            <div className="h-7 w-px bg-soc-800" />
            <div>
              <div className="text-soc-500 text-[10px] uppercase">Events Extracted</div>
              <div className="text-soc-100 font-bold mt-0.5">{events.length} Evidence Nodes</div>
            </div>
          </div>
        </div>
      </Card>

      {/* Filter & Control Bar */}
      <div className="flex flex-col md:flex-row gap-2 items-center justify-between bg-soc-950 p-2.5 rounded border border-soc-800">
        <div className="flex-1 flex gap-2 w-full md:w-auto">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-soc-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search timeline events, IPs, domains, indicators..."
              className="w-full bg-soc-900 border border-soc-800 rounded px-3 py-1.5 pl-8 text-xs font-mono text-soc-100 placeholder-soc-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-soc-900 border border-soc-800 rounded px-2.5 py-1.5 text-xs font-mono text-soc-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
            <option value="CLEAN">Clean</option>
          </select>

          {/* Event Type Filter */}
          <select
            value={selectedEventType}
            onChange={(e) => setSelectedEventType(e.target.value)}
            className="bg-soc-900 border border-soc-800 rounded px-2.5 py-1.5 text-xs font-mono text-soc-300 focus:outline-none focus:border-blue-500 hidden sm:block"
          >
            <option value="ALL">All Event Types</option>
            <option value="SMTP_RELAY">SMTP Relays</option>
            <option value="AUTHENTICATION_CHECK">Auth Checks</option>
            <option value="THREAT_INDICATOR">Threat Indicators</option>
            <option value="ATTACHMENT_DISCOVERED">Attachments</option>
            <option value="URL_DISCOVERED">URLs</option>
            <option value="DOMAIN_DISCOVERED">Domains</option>
            <option value="GEOLOCATION_RESOLVED">Geolocation</option>
          </select>
        </div>

        {/* Sort Toggle */}
        <button
          type="button"
          onClick={() => setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc')}
          className="px-3 py-1.5 bg-soc-900 hover:bg-soc-800 border border-soc-800 rounded text-xs font-mono text-soc-300 flex items-center gap-1.5 transition-colors self-end md:self-auto"
        >
          <ArrowUpDown className="w-3.5 h-3.5 text-blue-400" />
          <span>{sortOrder === 'asc' ? 'Chronological (Asc)' : 'Newest First (Desc)'}</span>
        </button>
      </div>

      {/* Main Timeline View */}
      <Card title={`Chronological Event Sequence (${filteredEvents.length} Events)`}>
        {loading ? (
          <div className="py-12 text-center text-xs font-mono text-soc-500">
            Reconstructing evidence hop chain and timeline...
          </div>
        ) : error ? (
          <div className="p-4 bg-red-950/40 border border-red-800 text-red-300 text-xs font-mono rounded flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="py-12 text-center text-xs font-mono text-soc-500">
            No events match the active filter criteria.
          </div>
        ) : (
          <div className="relative pl-6 sm:pl-8 border-l-2 border-soc-800/80 space-y-6 my-2">
            {filteredEvents.map((evt) => {
              const isExpanded = !!expandedEvents[evt.event_id];
              const isCopied = copiedId === evt.event_id;

              return (
                <div key={evt.event_id} className="relative group">
                  {/* Timeline Dot Marker */}
                  <span
                    className={`absolute -left-[31px] sm:-left-[39px] top-1.5 w-3.5 h-3.5 rounded-full border-2 ${getDotColorClass(evt.severity)} transition-all`}
                  />

                  {/* Event Container */}
                  <div className="p-3.5 bg-soc-950 border border-soc-800/90 rounded space-y-2 hover:border-soc-700 transition-colors">
                    {/* Event Header */}
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        {getEventIcon(evt.event_type)}
                        <span className="text-xs font-bold text-soc-100 font-mono">{evt.title}</span>
                        <span className="text-[10px] font-mono text-soc-500 uppercase px-1.5 py-0.5 rounded bg-soc-900 border border-soc-800">
                          {evt.event_type}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        {evt.severity && (
                          <Badge variant="severity" severity={evt.severity as ThreatSeverity}>
                            {evt.severity}
                          </Badge>
                        )}
                        {evt.timestamp ? (
                          <span className="text-[11px] font-mono text-soc-400 flex items-center gap-1 bg-soc-900 px-2 py-0.5 rounded border border-soc-800">
                            <Clock className="w-3 h-3 text-soc-500" />
                            {new Date(evt.timestamp).toUTCString().replace('GMT', 'UTC')}
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono text-soc-500 flex items-center gap-1 bg-soc-900/60 px-1.5 py-0.5 rounded border border-soc-800">
                            <Clock className="w-3 h-3 text-soc-600" />
                            Timestamp unavailable (Evidence Extracted)
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Event Description */}
                    <p className="text-xs font-mono text-soc-300 leading-relaxed">
                      {evt.description}
                    </p>

                    {/* Evidence Reference Box */}
                    {evt.evidence_reference && (
                      <div className="p-2 bg-soc-900/80 rounded border border-soc-800/80 flex items-center justify-between gap-2 font-mono text-[11px]">
                        <div className="truncate text-soc-400">
                          <span className="text-soc-500 uppercase mr-1.5">Evidence:</span>
                          <span className="text-soc-200">{evt.evidence_reference}</span>
                        </div>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(evt.evidence_reference || '', evt.event_id)}
                          className="shrink-0 text-soc-400 hover:text-soc-200 transition-colors p-1 rounded hover:bg-soc-800 flex items-center gap-1 text-[10px]"
                          title="Copy evidence reference"
                        >
                          {isCopied ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400 font-bold">COPIED</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>COPY</span>
                            </>
                          )}
                        </button>
                      </div>
                    )}

                    {/* Technical Metadata Drawer */}
                    {evt.metadata && Object.keys(evt.metadata).length > 0 && (
                      <div>
                        <button
                          type="button"
                          onClick={() => toggleExpand(evt.event_id)}
                          className="text-[11px] font-mono text-blue-400 hover:text-blue-300 flex items-center gap-1 mt-1 transition-colors"
                        >
                          {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                          <span>{isExpanded ? 'Hide Technical Metadata' : 'View Full Event Metadata'}</span>
                        </button>

                        {isExpanded && (
                          <div className="mt-2 p-2.5 bg-soc-900 rounded border border-soc-800 font-mono text-[11px] text-soc-300 space-y-1">
                            {Object.entries(evt.metadata).map(([key, val]) => (
                              <div key={key} className="flex gap-2">
                                <span className="text-soc-500 uppercase">{key}:</span>
                                <span className="text-soc-200 truncate">{typeof val === 'object' ? JSON.stringify(val) : String(val)}</span>
                              </div>
                            ))}
                            <div className="pt-1 border-t border-soc-800 text-[10px] text-soc-500 flex justify-between">
                              <span>Source: {evt.source}</span>
                              <span>ID: {evt.event_id}</span>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
};
