import React, { createContext, useContext, useEffect, useState } from 'react';
import { api } from '../lib/api';

export type UserRole = 'OWNER' | 'ADMIN' | 'ANALYST' | 'VIEWER';

export interface User {
  id: string;
  email: string;
  name?: string | null;
  tenantId: string;
  role: UserRole;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
}

interface AuthContextType {
  user: User | null;
  tenant: Tenant | null;
  isLoading: boolean;
  selectedSiteId: string | null;
  setSelectedSiteId: (siteId: string | null) => void;
  timeWindow: '24h' | '7d' | '30d';
  setTimeWindow: (w: '24h' | '7d' | '30d') => void;
  login: (credentials: { email: string; password: string }) => Promise<void>;
  register: (data: {
    fullName: string;
    email: string;
    password: string;
    tenantName: string;
    tenantSlug: string;
  }) => Promise<void>;
  logout: () => Promise<void>;
  canMutatePolicies: boolean;
  canSubmitFeedback: boolean;
  canReviewFeedback: boolean;
  canManageTeam: boolean;
  canManageSites: boolean;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedSiteId, setSelectedSiteId] = useState<string | null>(null);
  const [timeWindow, setTimeWindow] = useState<'24h' | '7d' | '30d'>('24h');

  const fetchSession = async () => {
    try {
      const data = await api.auth.me();
      if (data && data.user) {
        setUser({
          id: data.user.id,
          email: data.user.email,
          name: data.user.name,
          tenantId: data.activeTenantId || data.tenant?.id,
          role: data.role as UserRole,
        });
        if (data.tenant) {
          setTenant({
            id: data.tenant.id,
            name: data.tenant.name,
            slug: data.tenant.slug,
          });
        }
      } else {
        setUser(null);
        setTenant(null);
      }
    } catch (e) {
      setUser(null);
      setTenant(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchSession();
  }, []);

  const login = async (credentials: { email: string; password: string }) => {
    const res = await api.auth.login(credentials);
    if (res && res.user) {
      setUser({
        id: res.user.id,
        email: res.user.email,
        name: res.user.name,
        tenantId: res.activeTenantId,
        role: res.role as UserRole,
      });
      // Fetch full tenant details
      await fetchSession();
    }
  };

  const register = async (data: {
    fullName: string;
    email: string;
    password: string;
    tenantName: string;
    tenantSlug: string;
  }) => {
    const res = await api.auth.register(data);
    if (res && res.user) {
      setUser({
        id: res.user.id,
        email: res.user.email,
        name: res.user.name,
        tenantId: res.tenant.id,
        role: 'OWNER',
      });
      setTenant({
        id: res.tenant.id,
        name: res.tenant.name,
        slug: res.tenant.slug,
      });
    }
  };

  const logout = async () => {
    try {
      await api.auth.logout();
    } finally {
      setUser(null);
      setTenant(null);
    }
  };

  const role = user?.role;
  const canMutatePolicies = role === 'OWNER' || role === 'ADMIN';
  const canSubmitFeedback = role === 'OWNER' || role === 'ADMIN' || role === 'ANALYST';
  const canReviewFeedback = role === 'OWNER' || role === 'ADMIN';
  const canManageTeam = role === 'OWNER' || role === 'ADMIN';
  const canManageSites = role === 'OWNER' || role === 'ADMIN';

  return (
    <AuthContext.Provider
      value={{
        user,
        tenant,
        isLoading,
        selectedSiteId,
        setSelectedSiteId,
        timeWindow,
        setTimeWindow,
        login,
        register,
        logout,
        canMutatePolicies,
        canSubmitFeedback,
        canReviewFeedback,
        canManageTeam,
        canManageSites,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
