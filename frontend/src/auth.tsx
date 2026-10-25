import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, setCsrf, setUnauthorizedHandler } from "./api";

export type User = { id: string; email: string; role: string; mfa_enabled: boolean };
type MeResponse = User & { csrf_token: string };

type AuthState = {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string, otp?: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const me = await api<MeResponse>("GET", "/auth/me");
      setCsrf(me.csrf_token);
      setUser({ id: me.id, email: me.email, role: me.role, mfa_enabled: me.mfa_enabled });
    } catch {
      setCsrf(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCsrf(null);
      setUser(null);
    });
    void refresh();
    return () => setUnauthorizedHandler(null);
  }, [refresh]);

  const login = useCallback(
    async (email: string, password: string, otp?: string) => {
      const body: Record<string, string> = { email, password };
      if (otp) body.otp = otp;
      const res = await api<{ csrf_token: string }>("POST", "/auth/login", body);
      setCsrf(res.csrf_token);
      await refresh();
    },
    [refresh],
  );

  const register = useCallback(
    async (email: string, password: string) => {
      await api("POST", "/auth/register", { email, password });
      await login(email, password);
    },
    [login],
  );

  const logout = useCallback(async () => {
    try {
      await api("POST", "/auth/logout");
    } catch {
      // clear the local state even if the server call fails
    }
    setCsrf(null);
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, loading, login, register, logout, refresh }),
    [user, loading, login, register, logout, refresh],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
