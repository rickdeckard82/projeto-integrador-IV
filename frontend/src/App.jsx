import React from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import RequireAuth from "./auth/RequireAuth.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import DashboardPage from "./pages/DashboardPage.jsx";
import DomainsPage from "./pages/DomainsPage.jsx";
import IpBatchesPage from "./pages/IpBatchesPage.jsx";
import IpConfigPreviewPage from "./pages/IpConfigPreviewPage.jsx";
import RpzPreviewPage from "./pages/RpzPreviewPage.jsx";
import OfficesListPage from "./pages/OfficesListPage.jsx";
import OfficeDetailPage from "./pages/OfficeDetailPage.jsx";
import GeneralPage from "./pages/GeneralPage.jsx";
import UsersPage from "./pages/UsersPage.jsx";
import CompanySettingsPage from "./pages/CompanySettingsPage.jsx";
import ParameterSettingsPage from "./pages/ParameterSettingsPage.jsx";
import WhitelistPage from "./pages/WhitelistPage.jsx";
import BackupPage from "./pages/BackupPage.jsx";
import CommunicationsPage from "./pages/CommunicationsPage.jsx";
import LogPage from "./pages/LogPage.jsx";
import RequireAbuseAccess from "./auth/RequireAbuseAccess.jsx";
import AbuseIncidentsPage from "./pages/AbuseIncidentsPage.jsx";
import AbuseIncidentDetailPage from "./pages/AbuseIncidentDetailPage.jsx";
import AbuseMessagesPage from "./pages/AbuseMessagesPage.jsx";
import AbuseMessageDetailPage from "./pages/AbuseMessageDetailPage.jsx";
import AbuseSettingsPage from "./pages/AbuseSettingsPage.jsx";
import CgnatRulesPage from "./pages/CgnatRulesPage.jsx";
import AbuseAuditPage from "./pages/AbuseAuditPage.jsx";

function abuse(element) {
  return <RequireAbuseAccess>{element}</RequireAbuseAccess>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/comunicados" element={<CommunicationsPage />} />
        <Route path="/offices" element={<OfficesListPage />} />
        <Route path="/offices/:officeId" element={<OfficeDetailPage />} />
        <Route path="/domains" element={<DomainsPage />} />
        <Route path="/ip-blocks" element={<IpBatchesPage />} />
        <Route path="/ip-blocks/preview" element={<IpConfigPreviewPage />} />
        <Route path="/rpz" element={<RpzPreviewPage />} />
        <Route path="/general" element={<GeneralPage />} />
        <Route path="/general/users" element={<UsersPage />} />
        <Route path="/general/company" element={<CompanySettingsPage />} />
        <Route path="/general/parameters" element={<ParameterSettingsPage />} />
        <Route path="/general/whitelist" element={<WhitelistPage />} />
        <Route path="/general/backup" element={<BackupPage />} />
        <Route path="/log" element={<LogPage />} />
        <Route path="/abuse" element={abuse(<AbuseIncidentsPage />)} />
        <Route path="/abuse/incidents/:incidentId" element={abuse(<AbuseIncidentDetailPage />)} />
        <Route path="/abuse/messages" element={abuse(<AbuseMessagesPage />)} />
        <Route path="/abuse/messages/:messageId" element={abuse(<AbuseMessageDetailPage />)} />
        <Route path="/abuse/audit" element={abuse(<AbuseAuditPage />)} />
        <Route path="/general/abuse" element={abuse(<AbuseSettingsPage />)} />
        <Route path="/general/cgnat" element={abuse(<CgnatRulesPage />)} />
      </Route>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
