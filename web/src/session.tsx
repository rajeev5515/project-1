import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, onUnauthorized, type User } from './api';

interface SessionState {
  user: User | null;
  loading: boolean;
  setUser: (u: User | null) => void;
  logout: () => Promise<void>;
}

const Ctx = createContext<SessionState>({ user: null, loading: true, setUser: () => {}, logout: async () => {} });
export const useSession = () => useContext(Ctx);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api<{ user: User }>('GET', '/api/auth/me')
      .then((r) => setUser(r.user))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
    // Any 401 anywhere (session revoked, expired, user deactivated) signs the UI out.
    return onUnauthorized(() => setUser(null));
  }, []);

  const logout = useCallback(async () => {
    try {
      await api('POST', '/api/auth/logout');
    } finally {
      setUser(null);
    }
  }, []);

  return <Ctx.Provider value={{ user, loading, setUser, logout }}>{children}</Ctx.Provider>;
}

// ------------------------------------------------------------------ theme
export function useTheme(): [boolean, () => void] {
  const [dark, setDark] = useState(() => {
    try {
      const saved = localStorage.getItem('tv-theme');
      if (saved) return saved === 'dark';
    } catch {
      /* storage unavailable */
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  });
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
    try {
      localStorage.setItem('tv-theme', dark ? 'dark' : 'light');
    } catch {
      /* ignore */
    }
  }, [dark]);
  return [dark, () => setDark((d) => !d)];
}
