import { useWorkspaceUser } from './components/WorkspaceUserContext';
import { UsersPage } from './pages/UsersPage';
import { BrowserRouter, Navigate, Route, Routes, useParams } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { DashboardPage } from './pages/DashboardPage';
import { AssetExplorerPage } from './pages/AssetExplorerPage';
import { FindingDetailPage } from './pages/FindingDetailPage';
import { PolicyCompliancePage } from './pages/PolicyCompliancePage';
import { AdvisoriesPage } from './pages/AdvisoriesPage';
import { ExportCenterPage } from './pages/ExportCenterPage';
import { UploadPage } from './pages/UploadPage';
import { WorkspaceAccess } from './components/WorkspaceAccess';
import './App.css';
import './upload.css';
import './theme.css';

function LegacyScanRedirect() {
  const { scanId } = useParams();
  return <Navigate to={`/scans/${scanId}`} replace />;
}

function WorkspaceRoutes() {
  const user = useWorkspaceUser();
  if (user?.role === 'admin') return <Routes><Route element={<Layout />}><Route path="admin/users" element={<UsersPage />} /><Route path="*" element={<Navigate to="/admin/users" replace />} /></Route></Routes>;
  return (
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<DashboardPage />} />
            <Route path="dashboard" element={<Navigate to="/" replace />} />
            <Route path="scans" element={<UploadPage />} />
            <Route path="scans/:scanId" element={<UploadPage />} />
            <Route path="scan/:scanId" element={<LegacyScanRedirect />} />
            <Route path="assets" element={<AssetExplorerPage />} />
            <Route path="assets/:id" element={<FindingDetailPage />} />
            <Route path="admin/users" element={<UsersPage />} />
            <Route path="admin" element={<Navigate to="/admin/users" replace />} />
            <Route path="users" element={<Navigate to="/admin/users" replace />} />
            <Route path="policies" element={<PolicyCompliancePage />} />
            <Route path="advisories" element={<AdvisoriesPage />} />
            <Route path="exports" element={<ExportCenterPage />} />
            <Route path="audit" element={<Navigate to="/exports" replace />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
  );
}

export function App() {
  return <WorkspaceAccess><BrowserRouter><WorkspaceRoutes /></BrowserRouter></WorkspaceAccess>;
}

export default App;
