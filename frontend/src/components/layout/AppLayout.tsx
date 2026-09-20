import React, { useEffect, useState, useCallback } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { NewInvestigationModal } from '../investigation/NewInvestigationModal';
import { fetchHealthStatus } from '../../services/healthService';

export const AppLayout: React.FC = () => {
  const [backendStatus, setBackendStatus] = useState<'online' | 'offline' | 'loading'>('loading');
  const [backendVersion, setBackendVersion] = useState<string | undefined>(undefined);
  const [isNewInvestigationOpen, setIsNewInvestigationOpen] = useState<boolean>(false);

  const checkHealth = useCallback(async () => {
    try {
      setBackendStatus('loading');
      const health = await fetchHealthStatus();
      if (health && health.status === 'ok') {
        setBackendStatus('online');
        setBackendVersion(health.version || 'v0.1.0');
      } else {
        setBackendStatus('offline');
      }
    } catch {
      setBackendStatus('offline');
    }
  }, []);

  useEffect(() => {
    checkHealth();
    // Poll API health every 30s
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-soc-950 font-sans">
      {/* Primary Sidebar */}
      <Sidebar />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header */}
        <Header
          backendStatus={backendStatus}
          backendVersion={backendVersion}
          onRefreshStatus={checkHealth}
          onOpenNewInvestigation={() => setIsNewInvestigationOpen(true)}
        />

        {/* Content View Container */}
        <main className="flex-1 overflow-y-auto p-6 bg-soc-950">
          <div className="max-w-7xl mx-auto space-y-6">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Global New Investigation Modal */}
      <NewInvestigationModal
        isOpen={isNewInvestigationOpen}
        onClose={() => setIsNewInvestigationOpen(false)}
      />
    </div>
  );
};
