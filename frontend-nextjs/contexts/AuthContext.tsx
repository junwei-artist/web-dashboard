'use client';

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { api } from '@/lib/api';

interface User {
  username: string;
  role: string;
}

interface AuthContextType {
  user: User | null;
  authenticated: boolean;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [authenticated, setAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  const checkAuth = async () => {
    try {
      const response = await api.checkAuth();
      if (response.data && response.data.authenticated) {
        setUser({
          username: response.data.username,
          role: response.data.role || 'viewer',
        });
        setAuthenticated(true);
      } else {
        setUser(null);
        setAuthenticated(false);
      }
    } catch (error: any) {
      // Don't treat 401 as an error on login page - it's expected
      if (error.response?.status === 401 && pathname === '/login') {
        setUser(null);
        setAuthenticated(false);
      } else if (error.response?.status !== 401) {
        // Only log non-401 errors
        console.error('Auth check error:', error);
      }
      setUser(null);
      setAuthenticated(false);
    } finally {
      setLoading(false);
    }
  };

  const login = async (username: string, password: string) => {
    try {
      await api.login(username, password);
      await checkAuth();
      router.push('/');
      router.refresh();
    } catch (error) {
      throw error;
    }
  };

  const logout = async () => {
    try {
      await api.logout();
      setUser(null);
      setAuthenticated(false);
      router.push('/login');
      router.refresh();
    } catch (error) {
      console.error('Logout error:', error);
      // Still clear local state even if API call fails
      setUser(null);
      setAuthenticated(false);
      router.push('/login');
    }
  };

  useEffect(() => {
    // Initial auth check
    checkAuth();
  }, []);

  // Re-check auth when pathname changes (but not on login page)
  // Use a ref to prevent multiple simultaneous checks
  const checkingRef = React.useRef(false);
  
  useEffect(() => {
    if (pathname !== '/login' && !loading && !checkingRef.current) {
      checkingRef.current = true;
      checkAuth().finally(() => {
        checkingRef.current = false;
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname]);

  return (
    <AuthContext.Provider
      value={{
        user,
        authenticated,
        loading,
        login,
        logout,
        checkAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

