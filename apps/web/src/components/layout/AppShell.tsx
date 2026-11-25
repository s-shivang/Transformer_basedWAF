import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  Globe,
  Sliders,
  MessageSquareWarning,
  Users,
  ChevronLeft,
  ChevronRight,
  Shield,
  Search,
  Bell,
  Settings,
  Pin,
  LogOut,
  User as UserIcon,
  ChevronDown,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { ThemeToggle } from '../common/ThemeToggle';
import { cn } from '../../lib/utils';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../lib/api';

export const AppShell: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const { user, tenant, logout } = useAuth();
  const navigate = useNavigate();

  // Fetch pending feedback count for badge
  const { data: feedbackData } = useQuery({
    queryKey: ['feedback-pending-count'],
    queryFn: () => api.feedback.list({ reviewStatus: 'PENDING_REVIEW' }),
    refetchInterval: 30000,
  });

  // Fetch recent high-risk / blocked events for threat count badge
  const { data: recentEventsData } = useQuery({
    queryKey: ['threat-count-badge'],
    queryFn: () => api.events.query({ limit: 50, action: 'BLOCK' }),
    refetchInterval: 30000,
  });

  // Fetch notifications
  const { data: notificationsData } = useQuery({
    queryKey: ['notifications-list'],
    queryFn: () => api.notifications.list({ isRead: false }),
    refetchInterval: 30000,
  });

  const pendingFeedbackCount = feedbackData?.total ?? 3;
  const threatCount = recentEventsData?.total ?? 12;
  const unreadNotifications = notificationsData?.items?.length ?? 3;

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/events?pathContains=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  const navItems = [
    { label: 'Dashboard', to: '/', icon: LayoutDashboard },
    { label: 'Threats', to: '/events', icon: ShieldAlert, badge: threatCount > 0 ? threatCount : undefined },
    {
      label: 'Feedback Queue',
      to: '/feedback',
      icon: MessageSquareWarning,
      badge: pendingFeedbackCount > 0 ? pendingFeedbackCount : undefined,
    },
    { label: 'Protected Sites', to: '/sites', icon: Globe },
    { label: 'WAF Policies', to: '/policies', icon: Sliders },
    { label: 'Team & RBAC', to: '/team', icon: Users },
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#F9FAFB] dark:bg-[#000000] text-[#0A0A0A] dark:text-[#FFFFFF] font-sans">
      {/* 1. Left Sidebar (240px, neutral carbon black / white) */}
      <aside
        className={cn(
          'flex flex-col border-r transition-all duration-300 z-30 select-none shrink-0',
          'bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222]',
          collapsed ? 'w-[72px]' : 'w-[240px]',
        )}
      >
        {/* Brand Header */}
        <div
          className={cn(
            'h-16 flex items-center border-b border-[#E5E7EB] dark:border-[#222222] transition-all relative',
            collapsed ? 'justify-center px-2' : 'justify-between px-4',
          )}
        >
          {collapsed ? (
            /* Collapsed State: Centered Shield Logo matching reference ss2 */
            <>
              <button
                type="button"
                onClick={() => setCollapsed(false)}
                title="Expand sidebar"
                className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#FF6600] to-[#EA580C] flex items-center justify-center shrink-0 shadow-[0_0_16px_rgba(255,102,0,0.35)] hover:scale-105 transition-transform cursor-pointer"
              >
                <Shield className="w-5 h-5 text-white" />
              </button>
              <button
                type="button"
                onClick={() => setCollapsed(false)}
                aria-label="Expand sidebar"
                className="absolute -right-3 top-5 w-6 h-6 rounded-full border bg-white dark:bg-[#111111] border-[#E5E7EB] dark:border-[#333333] flex items-center justify-center shadow-md text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white hover:border-[#FF6600] z-40 transition-transform hover:scale-110"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </>
          ) : (
            /* Expanded State: Logo + Title + Collapse Chevron */
            <>
              <div className="flex items-center gap-3 overflow-hidden">
                <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#FF6600] to-[#EA580C] flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(255,102,0,0.3)]">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <div className="flex flex-col leading-tight overflow-hidden">
                  <div className="flex items-center gap-1.5 font-bold text-base tracking-tight">
                    <span className="text-[#0A0A0A] dark:text-white">Transformer</span>
                    <span className="text-[#EA580C] dark:text-[#FF7A1A]">WAF</span>
                  </div>
                  <span className="text-xs text-[#71717A] dark:text-[#A1A1AA] truncate font-normal">
                    {tenant?.name || 'Threat Intelligence'}
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setCollapsed(true)}
                aria-label="Collapse sidebar"
                className="p-1.5 rounded-lg text-[#71717A] hover:text-[#0A0A0A] dark:text-[#A1A1AA] dark:hover:text-white hover:bg-[#F3F4F6] dark:hover:bg-[#161616] transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            </>
          )}
        </div>

        {/* Primary Navigation Links */}
        <nav className="flex-1 px-3 py-4 space-y-1.5 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-xl text-sm transition-all relative group',
                  collapsed ? 'w-10 h-10 mx-auto justify-center px-0' : 'px-3.5 py-2.5',
                  isActive
                    ? 'bg-[#FFF7ED] border border-[#FFEDD5] text-[#EA580C] font-semibold dark:bg-gradient-to-r dark:from-[#FF6600]/80 dark:to-[#EA580C]/40 dark:border-[#FF6600]/40 dark:text-white dark:shadow-[0_0_15px_rgba(255,102,0,0.35)]'
                    : 'text-[#71717A] dark:text-[#A1A1AA] hover:bg-[#F3F4F6] dark:hover:bg-[#161616] hover:text-[#0A0A0A] dark:hover:text-white font-medium',
                )
              }
              title={collapsed ? item.label : undefined}
            >
              <item.icon className="w-4 h-4 shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
              {item.badge !== undefined && (
                <span
                  className={cn(
                    'px-2 py-0.5 rounded-full text-xs font-mono font-medium leading-none',
                    'bg-[#F3F4F6] text-[#71717A] border border-[#E5E7EB] dark:bg-[#161616] dark:text-[#A1A1AA] dark:border-[#262626]',
                    collapsed ? 'absolute top-1 right-1 text-[10px] px-1 py-0' : 'ml-auto',
                  )}
                >
                  {item.badge}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Bottom Pinned Status & Settings Cards */}
        <div className="p-3 border-t border-[#E5E7EB] dark:border-[#222222] space-y-2">
          <NavLink
            to="/policies"
            className={cn(
              'flex items-center gap-3 rounded-xl text-sm font-medium text-[#71717A] dark:text-[#A1A1AA] hover:bg-[#F3F4F6] dark:hover:bg-[#161616] hover:text-[#0A0A0A] dark:hover:text-white transition-colors',
              collapsed ? 'w-10 h-10 mx-auto justify-center' : 'px-3.5 py-2',
            )}
            title={collapsed ? 'Settings' : undefined}
          >
            <Settings className="w-4 h-4 shrink-0" />
            {!collapsed && <span>Settings</span>}
          </NavLink>

          {/* System Online Status Card */}
          <div
            className={cn(
              'flex items-center rounded-xl border transition-colors',
              'bg-[#F9FAFB] border-[#E5E7EB] dark:bg-[#111111] dark:border-[#222222]',
              collapsed
                ? 'w-10 h-10 mx-auto justify-center p-0'
                : 'justify-between p-2.5 gap-2.5',
            )}
            title={collapsed ? 'System Online: Latency <2ms' : undefined}
          >
            {!collapsed && (
              <div className="flex items-center gap-2 overflow-hidden">
                <Pin className="w-3.5 h-3.5 text-[#71717A] dark:text-[#A1A1AA]" />
                <span className="text-sm font-medium text-[#0A0A0A] dark:text-white truncate">
                  System Online
                </span>
              </div>
            )}
            <span className="relative flex h-2.5 w-2.5 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#10B981]" />
            </span>
          </div>
        </div>
      </aside>

      {/* 2. Main Content Container */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Sticky Top Header Bar (64px) */}
        <header className="h-16 border-b shrink-0 flex items-center justify-between px-6 bg-white dark:bg-[#000000] border-[#E5E7EB] dark:border-[#222222] z-20 gap-4">
          {/* Left/Center Command Search Bar */}
          <form onSubmit={handleSearchSubmit} className="flex-1 max-w-xl">
            <div className="relative flex items-center">
              <Search className="w-4 h-4 absolute left-3.5 text-[#71717A] dark:text-[#A1A1AA] pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search threats, IPs, domains, or keywords..."
                className={cn(
                  'w-full h-10 pl-10 pr-12 rounded-xl text-sm font-sans border transition-colors',
                  'bg-[#F3F4F6] border-[#E5E7EB] text-[#0A0A0A] placeholder-[#71717A] focus:bg-white focus:border-[#EA580C] focus:outline-none focus:ring-1 focus:ring-[#EA580C]',
                  'dark:bg-[#111111] dark:border-[#222222] dark:text-white dark:placeholder-[#71717A] dark:focus:bg-[#161616] dark:focus:border-[#FF6600] dark:focus:ring-[#FF6600]',
                )}
              />
              <span className="absolute right-3 px-1.5 py-0.5 rounded text-xs font-mono font-medium bg-[#E5E7EB] dark:bg-[#222222] text-[#71717A] dark:text-[#A1A1AA] pointer-events-none">
                ⌘K
              </span>
            </div>
          </form>

          {/* Right Header Controls (Notifications, ThemeToggle, Profile) */}
          <div className="flex items-center gap-3 shrink-0">
            {/* Notification Bell */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowNotifications(!showNotifications)}
                aria-label="View notifications"
                className={cn(
                  'w-9 h-9 rounded-xl flex items-center justify-center border transition-colors relative',
                  'bg-white border-[#E5E7EB] text-[#52525B] hover:bg-[#F3F4F6]',
                  'dark:bg-[#111111] dark:border-[#222222] dark:text-[#A1A1AA] dark:hover:text-white dark:hover:bg-[#161616]',
                )}
              >
                <Bell className="w-4 h-4" />
                {unreadNotifications > 0 && (
                  <span className="absolute -top-1 -right-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-red-500 text-white shadow-xs">
                    {unreadNotifications}
                  </span>
                )}
              </button>

              {/* Notifications Dropdown */}
              {showNotifications && (
                <div
                  className={cn(
                    'absolute right-0 mt-2 w-80 rounded-xl border p-3.5 z-50 shadow-xl',
                    'bg-white border-[#E5E7EB] text-[#0A0A0A] dark:bg-[#0A0A0A] dark:border-[#222222] dark:text-white',
                  )}
                >
                  <div className="flex items-center justify-between pb-2 border-b border-[#E5E7EB] dark:border-[#222222] mb-2">
                    <span className="text-sm font-semibold">Security Notifications</span>
                    <span className="text-xs font-mono text-[#FF6600]">{unreadNotifications} unread</span>
                  </div>
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    <div className="p-2.5 rounded-lg bg-[#F9FAFB] dark:bg-[#161616] text-xs">
                      <div className="font-semibold text-red-500 text-xs">ATTACK_SPIKE Detected</div>
                      <div className="text-xs text-[#71717A] dark:text-[#A1A1AA] mt-0.5">
                        Multiple blocked requests on site API Gateway
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#F9FAFB] dark:bg-[#161616] text-xs">
                      <div className="font-semibold text-[#FF8800] text-xs">ML_DEGRADED</div>
                      <div className="text-xs text-[#71717A] dark:text-[#A1A1AA] mt-0.5">
                        ML model fail_open activated temporarily
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Pill Sun/Moon Theme Toggle */}
            <ThemeToggle />

            {/* User Profile Menu */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowProfileMenu(!showProfileMenu)}
                className={cn(
                  'flex items-center gap-2.5 pl-2 pr-3 py-1.5 rounded-full border transition-colors',
                  'bg-white border-[#E5E7EB] hover:bg-[#F3F4F6] text-[#0A0A0A]',
                  'dark:bg-[#111111] dark:border-[#222222] dark:hover:bg-[#161616] dark:text-white',
                )}
              >
                <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-[#FF6600] to-[#EA580C] flex items-center justify-center text-xs font-bold text-white shrink-0 shadow-sm">
                  {(user?.name || user?.email || 'N')[0].toUpperCase()}
                </div>
                <div className="hidden sm:flex flex-col text-left leading-tight">
                  <span className="text-sm font-semibold truncate max-w-[130px]">
                    {user?.name || user?.email?.split('@')[0] || 'Noah Turner'}
                  </span>
                  <span className="text-xs text-[#71717A] dark:text-[#A1A1AA]">
                    {user?.role === 'OWNER' ? 'Principal SecOps Architect' : user?.role || 'Security Analyst'}
                  </span>
                </div>
                <ChevronDown className="w-3.5 h-3.5 text-[#71717A] dark:text-[#A1A1AA]" />
              </button>

              {/* Profile Dropdown Menu */}
              {showProfileMenu && (
                <div
                  className={cn(
                    'absolute right-0 mt-2 w-52 rounded-xl border p-2 z-50 shadow-xl',
                    'bg-white border-[#E5E7EB] text-[#0A0A0A] dark:bg-[#0A0A0A] dark:border-[#222222] dark:text-white',
                  )}
                >
                  <div className="px-3 py-2 border-b border-[#E5E7EB] dark:border-[#222222] text-xs">
                    <div className="font-semibold text-sm truncate">{user?.name || user?.email}</div>
                    <div className="text-xs font-mono text-[#FF6600] uppercase mt-0.5">{user?.role}</div>
                  </div>
                  <NavLink
                    to="/team"
                    onClick={() => setShowProfileMenu(false)}
                    className="flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm hover:bg-[#F3F4F6] dark:hover:bg-[#161616] transition-colors font-medium"
                  >
                    <UserIcon className="w-4 h-4 text-[#71717A] dark:text-[#A1A1AA]" />
                    <span>Team & Members</span>
                  </NavLink>
                  <button
                    type="button"
                    onClick={handleLogout}
                    className="w-full flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors font-medium"
                  >
                    <LogOut className="w-4 h-4" />
                    <span>Sign Out</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* 3. Scrollable Command Center Canvas */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#F9FAFB] dark:bg-[#000000]">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
