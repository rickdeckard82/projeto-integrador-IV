import React from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "./AuthContext.jsx";

// A API também recusa (403); isto só evita mostrar telas vazias.
export default function RequireAbuseAccess({ children }) {
  const { user } = useAuth();
  if (!user?.abuse_access) {
    return <Navigate to="/dashboard" replace />;
  }
  return children;
}
