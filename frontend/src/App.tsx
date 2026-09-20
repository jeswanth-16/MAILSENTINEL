import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/common/ProtectedRoute';
import { AppLayout } from './components/layout/AppLayout';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { ActiveCasesPage } from './pages/ActiveCasesPage';
import { InvestigationWorkbenchPage } from './pages/InvestigationWorkbenchPage';
import { CaseHistoryPage } from './pages/CaseHistoryPage';
import { CaseManagementPage } from './pages/CaseManagementPage';
import { CaseDetailsPage } from './pages/CaseDetailsPage';
import { EmailAnalyzerPage } from './pages/EmailAnalyzerPage';
import { UrlIntelligencePage } from './pages/UrlIntelligencePage';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage';
import { TimelinePage } from './pages/TimelinePage';
import { AttackGraphPage } from './pages/AttackGraphPage';
import { EvidencePage } from './pages/EvidencePage';
import { ThreatMapPage } from './pages/ThreatMapPage';
import { BlockchainVerificationPage } from './pages/BlockchainVerificationPage';
import { ReportsPage } from './pages/ReportsPage';
import { ReportCenterPage } from './pages/ReportCenterPage';
import { ReportViewerPage } from './pages/ReportViewerPage';
import { AdminUsersPage } from './pages/AdminUsersPage';
import { SecurityDashboardPage } from './pages/SecurityDashboardPage';
import { SettingsPage } from './pages/SettingsPage';
import { NotFoundPage } from './pages/NotFoundPage';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Authentication Route */}
          <Route path="/login" element={<LoginPage />} />

          {/* Protected SOC Routes */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Navigate to="/dashboard" replace />} />

            {/* Overview */}
            <Route path="dashboard" element={<DashboardPage />} />

            {/* Incident Response & SOC Case Management */}
            <Route path="cases" element={<CaseManagementPage />} />
            <Route path="cases/:caseId" element={<CaseDetailsPage />} />

            {/* Investigations */}
            <Route path="investigations/active" element={<ActiveCasesPage />} />
            <Route path="investigations/:id" element={<InvestigationWorkbenchPage />} />
            <Route path="investigations/history" element={<CaseHistoryPage />} />

            {/* Analysis */}
            <Route path="analysis/email" element={<EmailAnalyzerPage />} />
            <Route path="analysis/url" element={<UrlIntelligencePage />} />
            <Route path="analysis/threat" element={<ThreatIntelligencePage />} />

            {/* Forensics */}
            <Route path="forensics/timeline" element={<TimelinePage />} />
            <Route path="forensics/attack-graph" element={<AttackGraphPage />} />
            <Route path="forensics/evidence" element={<EvidencePage />} />

            {/* Intelligence */}
            <Route path="intelligence/map" element={<ThreatMapPage />} />

            {/* Blockchain */}
            <Route path="blockchain/verification" element={<BlockchainVerificationPage />} />

            {/* Reports */}
            <Route path="reports" element={<ReportCenterPage />} />
            <Route path="reports/view/:caseId" element={<ReportViewerPage />} />
            <Route path="reports/dossier" element={<ReportsPage />} />

            {/* Administration & Security */}
            <Route
              path="admin/users"
              element={
                <ProtectedRoute allowedRoles={['ADMIN']}>
                  <AdminUsersPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="admin/security"
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'AUDITOR']}>
                  <SecurityDashboardPage />
                </ProtectedRoute>
              }
            />

            {/* Settings */}
            <Route path="settings" element={<SettingsPage />} />

            {/* Fallback */}
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;
