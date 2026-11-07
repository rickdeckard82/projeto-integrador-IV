import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import * as authApi from "../api/auth.js";
import { getToken, setToken, setUnauthorizedHandler } from "../api/client.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [status, setStatus] = useState("loading"); // loading | authenticated | anonymous

  const clearSession = useCallback(() => {
    setToken(null);
    setUser(null);
    setStatus("anonymous");
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(clearSession);
  }, [clearSession]);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setStatus("anonymous");
      return;
    }
    authApi
      .me()
      .then((data) => {
        if (data.type === "user") {
          setUser({ id: data.id, username: data.username, abuse_access: Boolean(data.abuse_access) });
        }
        setStatus("authenticated");
      })
      .catch(() => {
        clearSession();
      });
  }, [clearSession]);

  const login = useCallback(async (username, password) => {
    const data = await authApi.login(username, password);
    setToken(data.token);
    setUser(data.user);
    setStatus("authenticated");
    return data.user;
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      // token já pode estar inválido — não impede o logout local
    }
    clearSession();
  }, [clearSession]);

  const value = useMemo(
    () => ({ user, status, login, logout }),
    [user, status, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth deve ser usado dentro de um AuthProvider.");
  }
  return ctx;
}
