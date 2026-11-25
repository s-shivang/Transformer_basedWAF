import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Activity,
  Globe,
  Sliders,
  MessageSquareWarning,
  Users,
  ChevronLeft,
  ChevronRight,
  Shield,
  LogOut,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { ThemeToggle } from '../common/ThemeToggle';
import { cn } from '../../lib/utils';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../lib/api';

export const AppShell: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const { user, tenant, logout, selectedSiteId, setSelectedSiteId, timeWindow, setTimeWindow } =
    useAuth();
  const navigate = useNavigate();

  // Fetch sites for global site selector
  const { data: sites = [] } = useQuery({
    queryKey: ['sites'],
    queryFn: () => api.sites.list(),
  });

  // Fetch pending feedback count for badge
  const { data: feedbackData } = useQuery({
    queryKey: ['feedback-pending-count', selectedSiteId],
    queryFn: () => api.feedback.list({ reviewStatus: 'PENDING_REVIEW', siteId: selectedSiteId || undefined }),
    refetchInterval: 30000,
  });

  const pendingCount = feedbackData?.total || 0;

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const navItems = [
    { label: 'Overview', to: '/', icon: LayoutDashboard },
    { label: 'Security Events', to: '/events', icon: Activity },
    { label: 'Protected Sites', to: '/sites', icon: Globe },
    { label: 'WAF Policies', to: '/policies', icon: Sliders },
    {
      label: 'Feedback Queue',
      to: '/feedback',
      icon: MessageSquareWarning,
      badge: pendingCount > 0 ? pendingCount : undefined,
    },
    { label: 'Team & RBAC', to: '/team', icon: Users },
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-50 dark:bg-[#090D16] text-slate-900 dark:text-slate-50">
      {/* Collapsible Left Sidebar */}
      <aside
        className={cn(
          'flex flex-col border-r transition-all duration-300 z-30 select-none',
          'bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937]',
          collapsed ? 'w-[72px]' : 'w-[240px]',
        )}
      >
        {/* Brand Header */}
        <div className="h-14 flex items-center justify-between px-4 border-b border-slate-200 dark:border-[#1F2937]">
          <div className="flex items-center gap-2.5 overflow-hidden">
            <div className="w-8 h-8 rounded-lg bg-blue-600 dark:bg-blue-500 flex items-center justify-center shrink-0 shadow-sm">
              <Shield className="w-5 h-5 text-white" />
            </div>
            {!collapsed && (
              <div className="flex flex-col leading-tight overflow-hidden">
                <span className="font-semibold text-sm tracking-tight truncate">
                  Transformer WAF
                </span>
                <span className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                  {tenant?.name || 'Enterprise SOC'}
                </span>
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors relative group',
                  isActive
                    ? 'bg-blue-50 text-blue-700 dark:bg-blue-500/15 dark:text-blue-400 font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60 hover:text-slate-900 dark:hover:text-slate-200',
                  collapsed && 'justify-center px-0',
                )
              }
              title={collapsed ? item.label : undefined}
            >
              <item.icon className="w-5 h-5 shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
              {item.badge !== undefined && (
                <span
                  className={cn(
                    'px-1.5 py-0.5 rounded-full text-xs font-mono font-bold leading-none',
                    'bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300',
                    collapsed ? 'absolute top-1.5 right-1.5 text-[9px]' : 'ml-auto',
                  )}
                >
                  {item.badge}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Sidebar Footer User Card */}
        <div className="p-3 border-t border-slate-200 dark:border-[#1F2937]">
          <div className={cn('flex items-center gap-2.5', collapsed ? 'justify-center' : 'justify-between')}>
            <div className="flex items-center gap-2 overflow-hidden">
              <div className="w-7 h-7 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center text-xs font-bold text-slate-700 dark:text-slate-200 shrink-0">
                {(user?.name || user?.email || 'U')[0].toUpperCase()}
              </div>
              {!collapsed && (
                <div className="flex flex-col leading-tight overflow-hidden">
                  <span className="text-xs font-medium truncate">{user?.name || user?.email}</span>
                  <span className="text-[10px] font-mono text-blue-600 dark:text-blue-400 font-semibold">
                    {user?.role}
                  </span>
                </div>
              )}
            </div>
            {!collapsed && (
              <button
                type="button"
                onClick={handleLogout}
                title="Log Out"
                className="p-1.5 text-slate-400 hover:text-red-600 dark:hover:text-red-400 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                <LogOut className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Sticky Top Bar (56px) */}
        <header className="h-14 border-b shrink-0 flex items-center justify-between px-6 bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] z-20">
          <div className="flex items-center gap-4">
            {/* Global Site Selector */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-slate-500 dark:text-slate-400 hidden sm:inline">
                Site:
              </span>
              <select
                value={selectedSiteId || ''}
                onChange={(e) => setSelectedSiteId(e.target.value || null)}
                className="text-xs font-medium rounded-lg border px-2.5 py-1.5 bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="">All Protected Sites</option>
                {sites.map((s: any) => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({s.domain})
                  </option>
                ))}
              </select>
            </div>

            {/* Time Window Picker */}
            <div className="inline-flex rounded-lg p-0.5 bg-slate-100 dark:bg-[#090D16] border border-slate-200 dark:border-[#1F2937]">
              {(['24h', '7d', '30d'] as const).map((w) => (
                <button
                  key={w}
                  type="button"
                  onClick={() => setTimeWindow(w)}
                  className={cn(
                    'px-2.5 py-1 text-xs font-mono font-medium rounded-md transition-colors',
                    timeWindow === w
                      ? 'bg-white dark:bg-[#111827] text-blue-600 dark:text-blue-400 shadow-xs'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200',
                  )}
                >
                  {w}
                </button>
              ))}
            </div>
          </div>

          {/* Right Top Bar Controls */}
          <div className="flex items-center gap-3">
            <ThemeToggle />
            <div className="hidden sm:flex items-center gap-2 pl-3 border-l border-slate-200 dark:border-[#1F2937]">
              <span className="text-xs text-slate-500 dark:text-slate-400">Tenant:</span>
              <span className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-300">
                {tenant?.slug || 'alpha'}
              </span>
            </div>
          </div>
        </header>

        {/* Scrollable Data Workspace */}
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
