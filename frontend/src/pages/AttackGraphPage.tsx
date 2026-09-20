import React, { useEffect, useMemo, useState } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  MarkerType,
  useNodesState,
  useEdgesState,
  Position,
  Handle,
} from 'reactflow';
import 'reactflow/dist/style.css';

import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { 
  Share2, 
  Server, 
  Globe, 
  Link as LinkIcon, 
  FileText, 
  ShieldAlert, 
  Mail, 
  Layers, 
  MapPin, 
  Info
} from 'lucide-react';
import { getInvestigationGraph } from '../services/forensicsService';
import { AttackGraphResponse, GraphNode, GraphNodeType } from '../types/forensics';
import { ThreatSeverity } from '../types/investigation';

// Custom SOC Graph Node Component
const SocGraphNode = ({ data, selected }: { data: any; selected: boolean }) => {
  const node: GraphNode = data.node;


  const getNodeIcon = (type: GraphNodeType) => {
    switch (type) {
      case 'INVESTIGATION':
        return <Layers className="w-3.5 h-3.5 text-blue-400" />;
      case 'EMAIL':
        return <Mail className="w-3.5 h-3.5 text-blue-400" />;
      case 'IP':
        return <Server className="w-3.5 h-3.5 text-sky-400" />;
      case 'DOMAIN':
        return <Globe className="w-3.5 h-3.5 text-amber-400" />;
      case 'URL':
        return <LinkIcon className="w-3.5 h-3.5 text-purple-400" />;
      case 'ATTACHMENT':
        return <FileText className="w-3.5 h-3.5 text-red-400" />;
      case 'THREAT_INDICATOR':
        return <ShieldAlert className="w-3.5 h-3.5 text-threat-critical" />;
      case 'ASN':
        return <Server className="w-3.5 h-3.5 text-indigo-400" />;
      case 'LOCATION':
        return <MapPin className="w-3.5 h-3.5 text-emerald-400" />;
      default:
        return <Info className="w-3.5 h-3.5 text-soc-400" />;
    }
  };

  const getBorderColor = () => {
    if (selected) return 'border-blue-400 ring-2 ring-blue-500/50 shadow-[0_0_12px_rgba(59,130,246,0.5)]';
    if (node.severity === 'CRITICAL') return 'border-red-600 bg-red-950/30';
    if (node.severity === 'HIGH') return 'border-orange-600 bg-orange-950/25';
    if (node.severity === 'MEDIUM') return 'border-amber-600/70 bg-amber-950/20';
    if (node.severity === 'CLEAN') return 'border-emerald-600/70 bg-emerald-950/20';
    return 'border-soc-800 bg-soc-950';
  };

  return (
    <div className={`p-2.5 rounded border transition-all w-52 font-mono text-xs shadow-lg ${getBorderColor()}`}>
      <Handle type="target" position={Position.Top} className="!bg-soc-600 !w-2 !h-2" />
      
      {/* Node Header */}
      <div className="flex items-center justify-between gap-1 pb-1.5 border-b border-soc-800/80 mb-1.5">
        <div className="flex items-center gap-1.5 truncate">
          {getNodeIcon(node.type)}
          <span className="text-[10px] uppercase font-bold text-soc-400 tracking-wider truncate">
            {node.type}
          </span>
        </div>
        {node.severity && node.severity !== 'INFO' && (
          <Badge variant="severity" severity={node.severity as ThreatSeverity} size="sm">
            {node.severity}
          </Badge>
        )}
      </div>

      {/* Node Label */}
      <div className="font-bold text-soc-100 text-xs truncate" title={node.label}>
        {node.label}
      </div>

      {/* Node Subtitle / Metadata excerpt */}
      {node.metadata && (
        <div className="text-[10px] text-soc-400 truncate mt-1">
          {node.type === 'IP' && (node.metadata.country || node.metadata.asn || 'Routable Relay')}
          {node.type === 'ATTACHMENT' && (node.metadata.mime_type || `${node.metadata.size_bytes} bytes`)}
          {node.type === 'THREAT_INDICATOR' && (node.metadata.category || 'Heuristic')}
          {node.type === 'EMAIL' && (node.metadata.from || 'Parsed Message')}
          {node.type === 'DOMAIN' && `${node.metadata.occurrence_count || 1} hits`}
          {node.type === 'URL' && (node.metadata.scheme ? `${node.metadata.scheme}://` : 'Extracted Link')}
          {node.type === 'INVESTIGATION' && `Score: ${node.metadata.risk_score || 0}/100`}
        </div>
      )}

      <Handle type="source" position={Position.Bottom} className="!bg-soc-600 !w-2 !h-2" />
    </div>
  );
};

const nodeTypes = {
  socNode: SocGraphNode,
};

export const AttackGraphPage: React.FC = () => {
  const [investigationId, setInvestigationId] = useState<string>('INV-2026-00001');
  const [rawGraph, setRawGraph] = useState<AttackGraphResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    let isMounted = true;
    const fetchGraph = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await getInvestigationGraph(investigationId);
        if (isMounted) {
          setRawGraph(res);
          setSelectedNodeId(null);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || 'Failed to load attack graph.');
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchGraph();
    return () => { isMounted = false; };
  }, [investigationId]);

  // Compute hierarchical layout coordinates for nodes
  useEffect(() => {
    if (!rawGraph) return;

    // Filter nodes
    const filteredRawNodes = rawGraph.nodes.filter(n => {
      if (typeFilter !== 'ALL' && n.type !== typeFilter) return false;
      if (severityFilter !== 'ALL' && n.severity !== severityFilter) return false;
      return true;
    });

    const activeNodeIds = new Set(filteredRawNodes.map(n => n.id));

    // Categorize nodes into layers for clean hierarchical positioning
    const layer0 = filteredRawNodes.filter(n => n.type === 'INVESTIGATION');
    const layer1 = filteredRawNodes.filter(n => n.type === 'EMAIL');
    const layer2 = filteredRawNodes.filter(n => ['IP', 'DOMAIN', 'URL', 'ATTACHMENT'].includes(n.type));
    const layer3 = filteredRawNodes.filter(n => ['ASN', 'LOCATION', 'THREAT_INDICATOR'].includes(n.type));

    const layers = [layer0, layer1, layer2, layer3];
    const reactFlowNodes: Node[] = [];

    layers.forEach((layer, layerIdx) => {
      const y = 80 + layerIdx * 180;
      const totalWidth = layer.length * 260;
      const startX = Math.max(80, 500 - totalWidth / 2);

      layer.forEach((n, idx) => {
        reactFlowNodes.push({
          id: n.id,
          type: 'socNode',
          data: { node: n },
          position: { x: startX + idx * 260, y },
        });
      });
    });

    // Filter edges connecting existing active nodes
    const reactFlowEdges: Edge[] = rawGraph.edges
      .filter(e => activeNodeIds.has(e.source) && activeNodeIds.has(e.target))
      .map(e => {
        const isMaliciousEdge = e.type === 'TRIGGERS';
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.type,
          animated: isMaliciousEdge,
          style: {
            stroke: isMaliciousEdge ? '#ef4444' : '#475569',
            strokeWidth: isMaliciousEdge ? 2 : 1.5,
          },
          labelStyle: {
            fill: '#94a3b8',
            fontSize: 10,
            fontFamily: 'monospace',
          },
          labelBgStyle: {
            fill: '#090d16',
            fillOpacity: 0.9,
            stroke: '#1e293b',
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isMaliciousEdge ? '#ef4444' : '#475569',
          },
        };
      });

    setNodes(reactFlowNodes);
    setEdges(reactFlowEdges);
  }, [rawGraph, typeFilter, severityFilter, setNodes, setEdges]);

  const selectedNode = useMemo(() => {
    if (!rawGraph || !selectedNodeId) return null;
    return rawGraph.nodes.find(n => n.id === selectedNodeId) || null;
  }, [rawGraph, selectedNodeId]);

  const relatedEdges = useMemo(() => {
    if (!rawGraph || !selectedNodeId) return [];
    return rawGraph.edges.filter(e => e.source === selectedNodeId || e.target === selectedNodeId);
  }, [rawGraph, selectedNodeId]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <Share2 className="w-5 h-5 text-blue-400" />
            <span>OBSERVED_EVIDENCE_RELATIONSHIP_GRAPH</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Interactive structural relationship mapping: Sender → Observed Relays → Domains → URLs → Heuristic Indicators.
          </p>
        </div>

        {/* Investigation Switcher */}
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

      {/* Investigation Persistent Summary */}
      <Card className="bg-soc-900 border-soc-800">
        <div className="flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
          <div className="flex items-center gap-3">
            <div>
              <div className="text-soc-500 text-[10px] uppercase">Active Case</div>
              <div className="text-sm font-bold text-soc-100">{investigationId}</div>
            </div>
            <div className="h-7 w-px bg-soc-800" />
            <div>
              <div className="text-soc-500 text-[10px] uppercase">Graph Structure</div>
              <div className="text-soc-200 font-semibold">
                {rawGraph ? `${rawGraph.total_nodes} Nodes • ${rawGraph.total_edges} Edges` : 'Loading...'}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div>
              <div className="text-soc-500 text-[10px] uppercase">Verdict</div>
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
              <div className="text-soc-500 text-[10px] uppercase">Attribution Scope</div>
              <div className="text-soc-300 mt-0.5 font-bold">Observed Infrastructure</div>
            </div>
          </div>
        </div>
      </Card>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 bg-soc-950 p-2.5 rounded border border-soc-800 font-mono text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-soc-500 text-[11px]">Entity Filter:</span>
          {['ALL', 'IP', 'DOMAIN', 'URL', 'ATTACHMENT', 'THREAT_INDICATOR'].map((type) => (
            <button
              key={type}
              type="button"
              onClick={() => setTypeFilter(type)}
              className={`px-2 py-1 rounded text-[11px] transition-colors ${
                typeFilter === type
                  ? 'bg-blue-600 text-white font-bold'
                  : 'bg-soc-900 border border-soc-800 text-soc-400 hover:text-soc-200'
              }`}
            >
              {type}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-soc-500 text-[11px]">Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'CLEAN'].map((sev) => (
            <button
              key={sev}
              type="button"
              onClick={() => setSeverityFilter(sev)}
              className={`px-2 py-1 rounded text-[11px] transition-colors ${
                severityFilter === sev
                  ? 'bg-blue-600 text-white font-bold'
                  : 'bg-soc-900 border border-soc-800 text-soc-400 hover:text-soc-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Graph Canvas & Side Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main React Flow Graph Canvas */}
        <div className="lg:col-span-2">
          <Card title="Interactive Attack Infrastructure & Evidence Graph" noPadding>
            <div className="h-[540px] w-full bg-soc-950 rounded-b relative">
              {loading ? (
                <div className="h-full flex items-center justify-center font-mono text-xs text-soc-500">
                  Building relational evidence graph...
                </div>
              ) : error ? (
                <div className="p-6 text-center font-mono text-xs text-red-400">
                  {error}
                </div>
              ) : (
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  nodeTypes={nodeTypes}
                  onNodeClick={(_, node) => setSelectedNodeId(node.id)}
                  fitView
                  attributionPosition="bottom-right"
                  className="bg-soc-950"
                >
                  <Background color="#1e293b" gap={20} size={1} />
                  <Controls className="!bg-soc-900 !border-soc-800 !text-soc-300 fill-soc-300" />
                  <MiniMap
                    nodeColor={(n) => {
                      if (n.data?.node?.severity === 'CRITICAL') return '#ef4444';
                      if (n.data?.node?.severity === 'HIGH') return '#f97316';
                      if (n.data?.node?.severity === 'CLEAN') return '#10b981';
                      return '#3b82f6';
                    }}
                    maskColor="rgba(11, 15, 23, 0.8)"
                    className="!bg-soc-900 !border-soc-800"
                  />
                </ReactFlow>
              )}
            </div>
          </Card>
        </div>

        {/* Selected Entity Inspector Panel */}
        <div className="space-y-4">
          <Card title="Selected Entity Inspector">
            {selectedNode ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-soc-800">
                  <span className="text-soc-500 uppercase text-[10px]">Entity Node</span>
                  {selectedNode.severity && (
                    <Badge variant="severity" severity={selectedNode.severity as ThreatSeverity}>
                      {selectedNode.severity}
                    </Badge>
                  )}
                </div>

                <div className="p-2.5 bg-soc-950 rounded border border-soc-800">
                  <div className="text-[10px] text-soc-500 uppercase">Label</div>
                  <div className="text-soc-100 font-bold mt-0.5 break-all">{selectedNode.label}</div>
                  <div className="text-[11px] text-soc-400 mt-1">ID: {selectedNode.id}</div>
                </div>

                {/* Node Metadata Key-Values */}
                {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                  <div className="space-y-1.5 bg-soc-950/60 p-2.5 rounded border border-soc-800">
                    <div className="text-[10px] text-soc-500 uppercase font-bold mb-1">Observed Attributes</div>
                    {Object.entries(selectedNode.metadata).map(([k, v]) => (
                      <div key={k} className="text-[11px] flex justify-between gap-2 border-b border-soc-800/40 pb-1">
                        <span className="text-soc-500">{k}:</span>
                        <span className="text-soc-200 text-right truncate max-w-[180px]">
                          {typeof v === 'object' ? JSON.stringify(v) : String(v || 'N/A')}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Connected Relationships */}
                <div className="space-y-1.5">
                  <div className="text-[10px] text-soc-500 uppercase font-bold">
                    Connected Edges ({relatedEdges.length})
                  </div>
                  <div className="space-y-1 max-h-44 overflow-y-auto pr-1">
                    {relatedEdges.map((e) => (
                      <div
                        key={e.id}
                        className="p-2 bg-soc-950 rounded border border-soc-800 text-[11px] space-y-0.5"
                      >
                        <div className="flex items-center justify-between text-soc-300">
                          <span className="font-bold text-blue-400">{e.type}</span>
                          <span className="text-soc-500">Confidence: {(e.confidence * 100).toFixed(0)}%</span>
                        </div>
                        <div className="text-[10px] text-soc-500 truncate">
                          {e.source === selectedNode.id ? `→ ${e.target}` : `← ${e.source}`}
                        </div>
                        {e.evidence_reference && (
                          <div className="text-[10px] text-soc-400 truncate">
                            Evidence: {e.evidence_reference}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-xs font-mono text-soc-500">
                Click any node in the graph canvas to inspect its relationships and evidence.
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
};
