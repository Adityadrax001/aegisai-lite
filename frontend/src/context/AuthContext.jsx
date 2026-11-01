
import {
  createContext,
  useCallback,
  useEffect,
  useState,
} from "react";

import { authService } from "../services/authService";

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [admin, setAdmin] = useState(null);
  const [loading, setLoading] = useState(true);

  const refreshAdmin = useCallback(async () => {
    const data = await authService.getCurrentAdmin();
    setAdmin(data.admin);
    return data.admin;
  }, []);

  useEffect(() => {
    let active = true;

    authService.getCurrentAdmin()
      .then((data) => {
        if (active) setAdmin(data.admin);
      })
      .catch(() => {
        if (active) setAdmin(null);
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  const login = async (email, password) => {
    await authService.login(email, password);
    return refreshAdmin();
  };

async function logout() {
  const response = await fetch("/api/auth/logout", {
    method: "POST",
    credentials: "include",
    headers: {
      "X-Aegis-Request": "browser",
    },
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.message || "Logout failed");
  }

  setAdmin(null);
}

  return (
    <AuthContext.Provider
      value={{
        admin,
        loading,
        isAuthenticated: Boolean(admin),
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
