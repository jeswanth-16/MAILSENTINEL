import React, { useEffect, useRef, useState } from 'react';
import { Card } from '../components/common/Card';
import { 
  MapPin, 
  ShieldAlert, 
  Crosshair
} from 'lucide-react';
import L from 'leaflet';
import { lookupIP } from '../services/intelligenceService';
import { IPIntelligenceResult } from '../types/intelligence';

interface ObservedHop {
  ip: string;
  hopType: 'Sender Relay (Observed)' | 'Intermediate Transit' | 'Corporate Gateway' | 'Internal Mail Transfer';
  expectedLocation?: string;
}

const INITIAL_HOPS: ObservedHop[] = [
  { ip: '185.220.101.5', hopType: 'Sender Relay (Observed)', expectedLocation: 'Amsterdam, Netherlands' },
  { ip: '149.154.161.9', hopType: 'Intermediate Transit', expectedLocation: 'Frankfurt, Germany' },
  { ip: '192.0.2.1', hopType: 'Internal Mail Transfer', expectedLocation: 'RFC 5737 Doc Net' },
  { ip: '192.168.1.1', hopType: 'Internal Mail Transfer', expectedLocation: 'RFC 1918 Private Net' },
  { ip: '10.0.0.1', hopType: 'Internal Mail Transfer', expectedLocation: 'RFC 1918 Private Net' },
];

export const ThreatMapPage: React.FC = () => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const markersRef = useRef<L.Marker[]>([]);

  const [hops, setHops] = useState<ObservedHop[]>(INITIAL_HOPS);
  const [intelResults, setIntelResults] = useState<Record<string, IPIntelligenceResult>>({});
  const [selectedIP, setSelectedIP] = useState<string | null>('185.220.101.5');
  const [customIP, setCustomIP] = useState<string>('');


  // Fetch intelligence for all hops
  useEffect(() => {
    let isMounted = true;
    const fetchAll = async () => {
      const results: Record<string, IPIntelligenceResult> = {};
      for (const hop of hops) {
        try {
          const res = await lookupIP(hop.ip);
          results[hop.ip] = res;
        } catch {
          // Keep resilient
        }
      }
      if (isMounted) {
        setIntelResults(results);
      }
    };

    fetchAll();
    return () => { isMounted = false; };
  }, [hops]);


  // Initialize Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current) return;
    if (mapInstanceRef.current) return; // Prevent double init

    const map = L.map(mapContainerRef.current, {
      center: [51.505, 10.0],
      zoom: 4,
      minZoom: 2,
      maxZoom: 18,
      zoomControl: true,
      attributionControl: false,
    });

    // Dark-mode styled OpenStreetMap CartoDB Dark Matter tiles
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 19,
      subdomains: 'abcd',
    }).addTo(map);

    mapInstanceRef.current = map;

    return () => {
      map.remove();
      mapInstanceRef.current = null;
    };
  }, []);

  // Update Markers on Map when intelResults change
  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    // Clear existing markers
    markersRef.current.forEach(m => m.remove());
    markersRef.current = [];

    const coordinatesList: L.LatLngExpression[] = [];

    Object.values(intelResults).forEach((intel) => {
      if (intel.latitude && intel.longitude && intel.is_routable) {
        const isSelected = selectedIP === intel.ip;
        const isMalicious = intel.reputation === 'KNOWN_MALICIOUS' || intel.reputation === 'SUSPICIOUS';
        const color = isMalicious ? '#ef4444' : '#3b82f6';

        const customIcon = L.divIcon({
          className: 'custom-leaflet-marker',
          html: `
            <div style="
              width: ${isSelected ? '24px' : '18px'};
              height: ${isSelected ? '24px' : '18px'};
              background-color: ${color};
              border: 2px solid ${isSelected ? '#ffffff' : '#0b0f17'};
              border-radius: 50%;
              box-shadow: 0 0 10px ${color}80;
              display: flex;
              align-items: center;
              justify-content: center;
              cursor: pointer;
              transition: all 0.2s ease;
            ">
              <div style="width: 6px; height: 6px; background-color: white; border-radius: 50%;"></div>
            </div>
          `,
          iconSize: [24, 24],
          iconAnchor: [12, 12],
        });

        const marker = L.marker([intel.latitude, intel.longitude], { icon: customIcon })
          .addTo(map)
          .bindPopup(`
            <div style="font-family: monospace; font-size: 11px; color: #0b0f17; min-width: 180px;">
              <div style="font-weight: bold; color: ${color};">${intel.ip}</div>
              <div>Location: ${intel.city || ''}, ${intel.country || ''}</div>
              <div>ASN: ${intel.asn || 'N/A'}</div>
              <div>Org: ${intel.organization || 'N/A'}</div>
              <div>Reputation: ${intel.reputation}</div>
            </div>
          `);

        marker.on('click', () => {
          setSelectedIP(intel.ip);
        });

        markersRef.current.push(marker);
        coordinatesList.push([intel.latitude, intel.longitude]);
      }
    });

    // Draw routing line between routable coordinates
    if (coordinatesList.length > 1) {
      const polyline = L.polyline(coordinatesList, {
        color: '#60a5fa',
        weight: 2,
        opacity: 0.7,
        dashArray: '5, 8',
      }).addTo(map);
      markersRef.current.push(polyline as any);
    }

    if (coordinatesList.length > 0) {
      map.fitBounds(L.latLngBounds(coordinatesList), { padding: [50, 50], maxZoom: 6 });
    }
  }, [intelResults, selectedIP]);

  const handleAddHop = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customIP.trim()) return;
    const clean = customIP.trim();
    if (hops.some(h => h.ip === clean)) return;

    const newHop: ObservedHop = {
      ip: clean,
      hopType: 'Sender Relay (Observed)',
    };

    setHops(prev => [newHop, ...prev]);
    setSelectedIP(clean);
    setCustomIP('');
  };

  const routableHops = hops.filter(h => {
    const res = intelResults[h.ip];
    return res ? res.is_routable && res.latitude && res.longitude : true;
  });

  const unroutableHops = hops.filter(h => {
    const res = intelResults[h.ip];
    return res ? !res.is_routable : false;
  });

  const activeResult = selectedIP ? intelResults[selectedIP] : null;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-soc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-soc-100 font-mono flex items-center gap-2">
            <MapPin className="w-5 h-5 text-blue-400" />
            <span>OBSERVED_IP_INFRASTRUCTURE_MAP</span>
          </h1>
          <p className="text-xs text-soc-400 mt-0.5">
            Geographic visualization of observed Received hop relays, autonomous systems, and mail infrastructure.
          </p>
        </div>
      </div>

      {/* Mandatory SOC Attribution Disclaimer */}
      <div className="p-3.5 bg-amber-950/30 border border-amber-800/80 rounded flex items-start gap-3 font-mono text-xs text-amber-200">
        <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-amber-300">SOC DISCIPLINE NOTICE / ATTRIBUTION GUARD:</strong> Geolocation coordinates represent observed network routing infrastructure (bulletproof hosting relays, transit backbones, mail exchangers) and <strong>NOT</strong> the physical location of the threat actor. Private / RFC 1918 hops are strictly omitted from map plotting.
        </div>
      </div>

      {/* Map & Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Leaflet Map Viewport */}
        <div className="lg:col-span-2 space-y-4">
          <Card title="Interactive Relay & Infrastructure Map" noPadding>
            <div className="relative">
              <div ref={mapContainerRef} className="h-[460px] w-full rounded-b bg-soc-950 z-0" />
              
              {/* Map Overlay Badge */}
              <div className="absolute top-3 right-3 bg-soc-950/90 border border-soc-800 backdrop-blur px-2.5 py-1.5 rounded font-mono text-[11px] text-soc-300 z-[1000] flex items-center gap-2 shadow-lg">
                <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                <span>Observed Relays ({routableHops.length})</span>
              </div>
            </div>
          </Card>

          {/* Add Custom IP Filter / Test Form */}
          <Card title="Add Observed IP to Hop Map">
            <form onSubmit={handleAddHop} className="flex gap-2">
              <input
                type="text"
                value={customIP}
                onChange={(e) => setCustomIP(e.target.value)}
                placeholder="Enter IP address (e.g., 149.154.161.9)..."
                className="flex-1 bg-soc-950 border border-soc-700 rounded px-3 py-2 text-xs font-mono text-soc-100 placeholder-soc-500 focus:outline-none focus:border-blue-500"
              />
              <button
                type="submit"
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono font-semibold rounded transition-colors"
              >
                PLOT IP
              </button>
            </form>
          </Card>
        </div>

        {/* Side Panel: Selected Node Inspector & Hop List */}
        <div className="space-y-4">
          {/* Active Node Detail Card */}
          <Card title="Selected Node Inspector">
            {activeResult ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-soc-800">
                  <span className="text-soc-400">Target IP:</span>
                  <span className="font-bold text-soc-100 text-sm">{activeResult.ip}</span>
                </div>
                
                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-soc-950/60 p-2 rounded border border-soc-800">
                    <div className="text-[10px] text-soc-500 uppercase">Country / City</div>
                    <div className="text-soc-200 font-semibold mt-0.5 truncate">
                      {activeResult.country ? `${activeResult.city || ''}, ${activeResult.country}` : 'Private Range'}
                    </div>
                  </div>
                  <div className="bg-soc-950/60 p-2 rounded border border-soc-800">
                    <div className="text-[10px] text-soc-500 uppercase">Category</div>
                    <div className="text-soc-200 font-semibold mt-0.5">{activeResult.category}</div>
                  </div>
                </div>

                <div className="bg-soc-950/60 p-2 rounded border border-soc-800">
                  <div className="text-[10px] text-soc-500 uppercase">Autonomous System (ASN)</div>
                  <div className="text-soc-200 font-semibold mt-0.5">{activeResult.asn || 'None / Private'}</div>
                  <div className="text-[11px] text-soc-400 truncate mt-0.5">{activeResult.organization || '—'}</div>
                </div>

                <div className="bg-soc-950/60 p-2 rounded border border-soc-800">
                  <div className="text-[10px] text-soc-500 uppercase">Reputation & Source</div>
                  <div className="text-soc-200 font-semibold mt-0.5">{activeResult.reputation}</div>
                  <div className="text-[11px] text-soc-400 mt-0.5">{activeResult.source}</div>
                </div>

                {activeResult.latitude && activeResult.longitude && (
                  <button
                    type="button"
                    onClick={() => {
                      if (mapInstanceRef.current && activeResult.latitude && activeResult.longitude) {
                        mapInstanceRef.current.flyTo([activeResult.latitude, activeResult.longitude], 8, { duration: 1.2 });
                      }
                    }}
                    className="w-full py-1.5 bg-soc-800 hover:bg-soc-700 text-soc-200 text-xs font-mono rounded flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <Crosshair className="w-3.5 h-3.5 text-blue-400" />
                    <span>CENTER MAP ON NODE</span>
                  </button>
                )}
              </div>
            ) : (
              <div className="text-center py-6 text-xs font-mono text-soc-500">
                Select an IP node from the hop list to inspect telemetry.
              </div>
            )}
          </Card>

          {/* Observed Routable Hops */}
          <Card title="Mapped Public Hops">
            <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
              {routableHops.map((hop) => {
                const res = intelResults[hop.ip];
                const isSelected = selectedIP === hop.ip;
                return (
                  <div
                    key={hop.ip}
                    onClick={() => {
                      setSelectedIP(hop.ip);
                      if (mapInstanceRef.current && res?.latitude && res?.longitude) {
                        mapInstanceRef.current.flyTo([res.latitude, res.longitude], 7);
                      }
                    }}
                    className={`p-2.5 rounded border cursor-pointer transition-colors font-mono text-xs ${
                      isSelected
                        ? 'bg-blue-950/40 border-blue-600 text-soc-100'
                        : 'bg-soc-950/60 border-soc-800 hover:border-soc-700 text-soc-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold">{hop.ip}</span>
                      <span className="text-[10px] text-soc-400">{res?.country || 'Resolving...'}</span>
                    </div>
                    <div className="text-[11px] text-soc-500 mt-0.5 truncate">{hop.hopType}</div>
                  </div>
                );
              })}
            </div>
          </Card>
        </div>
      </div>

      {/* Unmapped / Private Network Hops Table */}
      <Card title="Unmapped / Private Subnet Hops (RFC 1918 & RFC 5737)">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-soc-800 text-soc-500 text-[11px] uppercase">
                <th className="py-2 px-3">IP Address</th>
                <th className="py-2 px-3">RFC Classification</th>
                <th className="py-2 px-3">Routable</th>
                <th className="py-2 px-3">Status</th>
                <th className="py-2 px-3">Reason / SOC Handling</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-800/60 text-soc-300">
              {unroutableHops.map((hop) => {
                const res = intelResults[hop.ip];
                return (
                  <tr key={hop.ip} className="hover:bg-soc-950/40">
                    <td className="py-2.5 px-3 font-bold text-soc-100">{hop.ip}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded bg-soc-950 border border-soc-800 text-[11px] text-blue-400">
                        {res?.category || 'PRIVATE'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-soc-500">False</td>
                    <td className="py-2.5 px-3 text-blue-400">SKIPPED</td>
                    <td className="py-2.5 px-3 text-soc-400">
                      {res?.status_message || 'Internal network hop — excluded from geographic map.'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
