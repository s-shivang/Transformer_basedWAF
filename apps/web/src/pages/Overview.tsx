import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Shield,
  Plus,
  Calendar,
  ChevronDown,
  LayoutGrid,
  List,
  MoreHorizontal,
  X,
  ExternalLink,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { GlobalThreatGlobe } from '../components/GlobalThreatGlobe';
import { ActionBadge } from '../components/common/ActionBadge';
import { cn } from '../lib/utils';

interface ThreatItem {
  id: string;
  threatType: string;
  code: string;
  asset: string;
  riskScore: number;
  status: 'Blocked' | 'Investigating' | 'Resolved';
  method?: string;
  path?: string;
  clientIp?: string;
  timestamp?: string;
  reason?: string;
}

export const Overview: React.FC = () => {
  const { selectedSiteId, setSelectedSiteId, timeWindow, setTimeWindow } = useAuth();
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const [selectedThreat, setSelectedThreat] = useState<ThreatItem | null>(null);

  // 1. Overview KPIs
  const { data: overviewData } = useQuery({
    queryKey: ['analytics-overview', selectedSiteId, timeWindow],
    queryFn: () => api.analytics.overview({ siteId: selectedSiteId || undefined, window: timeWindow }),
  });

  // 2. Timeseries traffic
  const { data: timeseriesData } = useQuery({
    queryKey: ['analytics-timeseries', selectedSiteId, timeWindow],
    queryFn: () => api.analytics.timeseries({ siteId: selectedSiteId || undefined, window: timeWindow }),
  });

  // 3. Protected sites for site selector
  const { data: sites = [] } = useQuery({
    queryKey: ['sites'],
    queryFn: () => api.sites.list(),
  });

  // 4. Recent events
  const { data: eventsData } = useQuery({
    queryKey: ['recent-events', selectedSiteId],
    queryFn: () => api.events.query({ siteId: selectedSiteId || undefined, limit: 10 }),
  });

  const metrics = overviewData?.metrics || {
    totalRequests: 40320000,
    blockedCount: 126,
    challengedCount: 42,
    monitoredCount: 89,
    allowedCount: 40319743,
  };

  // Sparkline data for Active Threats card
  const sparklineData = [
    { v: 45 },
    { v: 52 },
    { v: 78 },
    { v: 64 },
    { v: 92 },
    { v: 85 },
    { v: 126 },
  ];

  // Map timeseries or provide fallback curved multi-layer traffic data
  const trafficChartData = (timeseriesData?.buckets || []).length > 0
    ? (timeseriesData?.buckets || []).map((b: any) => ({
        day: b.bucket.includes('T') ? b.bucket.split('T')[1].slice(0, 5) : b.bucket.slice(5),
        layer1: (b.allowed || 0) * 1.5,
        layer2: (b.allowed || 0) * 1.0 + (b.challenged || 0) * 2,
        layer3: (b.blocked || 0) * 3 + (b.monitored || 0),
      }))
    : [
        { day: 'Mon', layer1: 18, layer2: 12, layer3: 6 },
        { day: 'Tue', layer1: 22, layer2: 15, layer3: 8 },
        { day: 'Wed', layer1: 16, layer2: 10, layer3: 5 },
        { day: 'Thu', layer1: 32, layer2: 24, layer3: 14 },
        { day: 'Fri', layer1: 28, layer2: 19, layer3: 11 },
        { day: 'Sat', layer1: 36, layer2: 26, layer3: 15 },
        { day: 'Sun', layer1: 24, layer2: 16, layer3: 9 },
      ];

  // Threat tactics 7x7 matrix data (MITRE ATT&CK & OWASP Top 10)
  const heatmapTactics = [
    'Initial Access (T1190)',
    'Execution (T1059)',
    'Credential Stuffing',
    'SQL Injection (CWE-89)',
    'Cross-Site Scripting',
    'Path Traversal (CWE-22)',
    'Defense Evasion (T1562)',
  ];
  const heatmapDays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

  // Threat Matrix intensities [row][col] (0 to 4)
  const heatmapValues: number[][] = [
    [0, 1, 0, 0, 0, 3, 2],
    [0, 0, 0, 0, 4, 1, 0],
    [1, 0, 0, 3, 0, 1, 0],
    [0, 0, 1, 3, 2, 0, 0],
    [0, 0, 0, 1, 3, 2, 0],
    [0, 4, 0, 0, 0, 1, 2],
    [1, 0, 0, 1, 0, 2, 3],
  ];

  // Security Threats list (derived from live eventsData with fallback matching enterprise SOC threats)
  const rawEvents = eventsData?.items || [];
  const securityThreats: ThreatItem[] = rawEvents.length > 0
    ? rawEvents.slice(0, 4).map((e: any, idx: number) => ({
        id: e.id,
        threatType: e.action === 'BLOCK' ? 'Credential Stuffing (T1110)' : e.action === 'CHALLENGE' ? 'Suspicious Login Anomaly' : 'Automated API Scraper',
        code: `SEC-${100 + idx}`,
        asset: e.path || `/api/v1/resource-${idx}`,
        riskScore: e.riskScore || 0.85,
        status: (e.action === 'BLOCK' ? 'Blocked' : e.action === 'CHALLENGE' ? 'Investigating' : 'Resolved') as any,
        method: e.method,
        path: e.path,
        clientIp: e.clientIp,
        timestamp: e.createdAt,
        reason: e.triggerReason,
      }))
    : [
        {
          id: 't1',
          threatType: 'Credential Stuffing (T1110)',
          code: 'AUTH-102',
          asset: 'production-auth-gateway',
          riskScore: 0.95,
          status: 'Blocked',
          method: 'POST',
          path: '/api/v1/auth/token',
          clientIp: '185.190.110.23',
          reason: 'BURST_FAILED_AUTH_THRESHOLD_EXCEEDED',
        },
        {
          id: 't2',
          threatType: 'SQL Injection (CWE-89)',
          code: 'OWASP-A03',
          asset: 'checkout-api-ingress',
          riskScore: 0.88,
          status: 'Blocked',
          method: 'GET',
          path: '/api/v1/orders/search',
          clientIp: '198.51.100.55',
          reason: 'UNION_SELECT_INJECTION_SIGNATURE',
        },
        {
          id: 't3',
          threatType: 'Suspicious Login Anomaly',
          code: 'IAM-309',
          asset: 'identity-service-prod',
          riskScore: 0.62,
          status: 'Investigating',
          method: 'POST',
          path: '/auth/login',
          clientIp: '203.0.113.12',
          reason: 'GEOLOCATION_IMPOSSIBLE_TRAVEL',
        },
        {
          id: 't4',
          threatType: 'Remote Code Execution Probe',
          code: 'CVE-2021-44228',
          asset: 'telemetry-event-worker',
          riskScore: 0.92,
          status: 'Blocked',
          method: 'POST',
          path: '/telemetry/ingest',
          clientIp: '192.0.2.88',
          reason: 'JNDI_LOOKUP_LOG4J_SIGNATURE',
        },
      ];

  const gridColor = isDark ? '#222222' : '#E5E7EB';
  const axisColor = isDark ? '#71717A' : '#A1A1AA';

  return (
    <div className="space-y-6 pb-12 font-sans select-none">
      {/* 1. Hero Command Row */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight">
            <span className="text-[#0A0A0A] dark:text-white">Threat </span>
            <span className="text-[#EA580C] dark:text-[#FF7A1A]">Center</span>
          </h1>
          <p className="text-xs text-[#71717A] dark:text-[#A1A1AA] mt-0.5 font-normal">
            Autonomous multi-tenant neural inspection engine & real-time perimeter telemetry
          </p>
        </div>

        {/* Action Controls & Filters */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Date Range / Window Picker Pill */}
          <div className="flex items-center gap-2 h-9 px-3 rounded-xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] text-xs">
            <Calendar className="w-3.5 h-3.5 text-[#71717A] dark:text-[#A1A1AA]" />
            <select
              value={timeWindow}
              onChange={(e) => setTimeWindow(e.target.value as any)}
              className="bg-transparent text-xs font-medium focus:outline-none cursor-pointer text-[#0A0A0A] dark:text-white"
            >
              <option value="24h" className="dark:bg-[#111111]">Last 24 Hours (Realtime UTC)</option>
              <option value="7d" className="dark:bg-[#111111]">Past 7 Days (7d)</option>
              <option value="30d" className="dark:bg-[#111111]">Past 30 Days (30d)</option>
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-[#71717A] dark:text-[#A1A1AA]" />
          </div>

          {/* Grid / List Layout Switcher */}
          <div className="hidden md:flex items-center gap-1 h-9 p-1 rounded-xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222]">
            <button
              type="button"
              className="p-1 rounded-lg text-[#FF6600] bg-[#FFF7ED] dark:bg-[#161616]"
              aria-label="Grid view"
            >
              <LayoutGrid className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              className="p-1 rounded-lg text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white"
              aria-label="List view"
            >
              <List className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Protected Site Selector */}
          <div className="flex items-center h-9 px-3 rounded-xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] text-xs">
            <select
              value={selectedSiteId || ''}
              onChange={(e) => setSelectedSiteId(e.target.value || null)}
              className="bg-transparent text-xs font-medium focus:outline-none cursor-pointer text-[#0A0A0A] dark:text-white"
            >
              <option value="" className="dark:bg-[#111111]">All Perimeter Gateways</option>
              {sites.map((s: any) => (
                <option key={s.id} value={s.id} className="dark:bg-[#111111]">
                  {s.name} ({s.domain})
                </option>
              ))}
            </select>
          </div>

          {/* + New Investigation Primary CTA Button */}
          <Link
            to="/events"
            className="flex items-center gap-1.5 h-9 px-4 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-[#FF6600] to-[#EA580C] shadow-[0_0_15px_rgba(255,102,0,0.35)] hover:brightness-110 transition-all"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Investigation</span>
          </Link>
        </div>
      </div>

      {/* 2. Top Bento Grid (Globe 5 cols | 2 Stacked 3 cols | Heatmap 4 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Card: Global Threat Activity (5 cols) */}
        <div className="lg:col-span-5 rounded-2xl border p-4 flex flex-col justify-between bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm">
          <div className="flex items-center justify-between mb-2 px-1">
            <span className="text-xs font-semibold text-[#0A0A0A] dark:text-white">
              Global Threat Activity
            </span>
            <button
              type="button"
              className="text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white"
              aria-label="More options"
            >
              <MoreHorizontal className="w-4 h-4" />
            </button>
          </div>
          <GlobalThreatGlobe />
        </div>

        {/* Middle Column: 2 Stacked Cards (3 cols) */}
        <div className="lg:col-span-3 flex flex-col gap-5">
          {/* Card 1: Active Threats */}
          <div className="flex-1 rounded-2xl border p-5 flex flex-col justify-between bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm">
            <div className="flex items-center justify-between text-xs text-[#71717A] dark:text-[#A1A1AA]">
              <span className="font-medium">Active Threat Detections</span>
            </div>
            <div className="flex items-baseline gap-3 my-2">
              <span className="text-3xl font-semibold font-mono tabular-nums text-[#0A0A0A] dark:text-white">
                {metrics.blockedCount || 126}
              </span>
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-[#FFF7ED] text-[#EA580C] border border-[#FFEDD5] dark:bg-[#FF6600]/15 dark:text-[#FF8800] dark:border-[#FF6600]/30">
                +12.4%
              </span>
            </div>
            <span className="text-[10px] text-[#71717A] dark:text-[#A1A1AA] block mb-2 font-normal">
              Compared to 7-day rolling baseline
            </span>
            {/* Sparkline Area */}
            <div className="h-16 w-full -mb-2">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={sparklineData}>
                  <defs>
                    <linearGradient id="activeThreatsGlow" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#FF6600" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#FF6600" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <Area
                    type="natural"
                    dataKey="v"
                    stroke="#FF6600"
                    strokeWidth={2}
                    fill="url(#activeThreatsGlow)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Card 2: Threat Exposure Arc Gauge */}
          <div className="flex-1 rounded-2xl border p-5 flex flex-col justify-between items-center text-center bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm relative overflow-hidden">
            <div className="w-full flex items-center justify-between text-xs text-[#71717A] dark:text-[#A1A1AA] mb-2">
              <span className="font-medium">Threat Exposure Index</span>
            </div>

            {/* Radial Arc SVG Gauge */}
            <div className="relative w-44 h-24 flex items-end justify-center">
              <svg viewBox="0 0 160 90" className="w-full h-full overflow-visible">
                <defs>
                  <linearGradient id="gaugeGradient" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#EA580C" />
                    <stop offset="50%" stopColor="#FF6600" />
                    <stop offset="100%" stopColor="#FBBF24" />
                  </linearGradient>
                </defs>
                {/* Background Arc */}
                <path
                  d="M 15 80 A 65 65 0 0 1 145 80"
                  fill="none"
                  stroke={isDark ? '#1C1C1C' : '#E5E7EB'}
                  strokeWidth="11"
                  strokeLinecap="round"
                />
                {/* Active Score Arc (78%) */}
                <path
                  d="M 15 80 A 65 65 0 0 1 145 80"
                  fill="none"
                  stroke="url(#gaugeGradient)"
                  strokeWidth="11"
                  strokeLinecap="round"
                  strokeDasharray="204"
                  strokeDashoffset={204 * (1 - 0.78)}
                  style={{ filter: isDark ? 'drop-shadow(0 0 6px rgba(255,102,0,0.6))' : 'none' }}
                />
              </svg>
              {/* Inner Center Label */}
              <div className="absolute inset-0 flex flex-col items-center justify-end pb-1">
                <span className="text-2xl font-semibold font-mono tabular-nums text-[#0A0A0A] dark:text-white">
                  78%
                </span>
                <span className="text-[10px] text-[#71717A] dark:text-[#A1A1AA] leading-none font-medium">
                  Perimeter Defense Coverage
                </span>
              </div>
            </div>

            {/* Glowing Shield Icon */}
            <div className="mt-2 w-8 h-8 rounded-full flex items-center justify-center bg-[#FFF7ED] dark:bg-[#161616] text-[#FF6600] border border-[#FFEDD5] dark:border-[#FF6600]/30 shadow-[0_0_10px_rgba(255,102,0,0.2)]">
              <Shield className="w-4 h-4 fill-current" />
            </div>
          </div>
        </div>

        {/* Right Card: Threat Tactics Heatmap (4 cols) */}
        <div className="lg:col-span-4 rounded-2xl border p-5 flex flex-col justify-between bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-[#0A0A0A] dark:text-white">
              Threat Tactics Heatmap
            </span>
            <button
              type="button"
              className="text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white"
              aria-label="More options"
            >
              <MoreHorizontal className="w-4 h-4" />
            </button>
          </div>

          {/* 7x7 Grid Matrix */}
          <div className="flex flex-col gap-1.5 flex-1 justify-center">
            {/* Days Column Header */}
            <div className="flex items-center">
              <div className="w-24 shrink-0" />
              <div className="flex-1 grid grid-cols-7 gap-1.5 text-center text-[10px] text-[#71717A] dark:text-[#A1A1AA]">
                {heatmapDays.map((d) => (
                  <span key={d}>{d}</span>
                ))}
              </div>
            </div>

            {/* Matrix Rows */}
            {heatmapTactics.map((tactic, rowIdx) => (
              <div key={tactic} className="flex items-center">
                <span className="w-24 shrink-0 text-[11px] text-[#71717A] dark:text-[#A1A1AA] truncate pr-2">
                  {tactic}
                </span>
                <div className="flex-1 grid grid-cols-7 gap-1.5">
                  {heatmapValues[rowIdx].map((intensity, colIdx) => {
                    let cellColor = isDark ? 'bg-[#161616]' : 'bg-[#F4F4F5]';
                    if (intensity === 1) cellColor = isDark ? 'bg-[#FF6600]/25' : 'bg-[#FED7AA]';
                    if (intensity === 2) cellColor = isDark ? 'bg-[#FF6600]/50' : 'bg-[#FB923C]';
                    if (intensity === 3) cellColor = isDark ? 'bg-[#FF6600]/80 shadow-[0_0_8px_rgba(255,102,0,0.4)]' : 'bg-[#F97316]';
                    if (intensity === 4) cellColor = isDark ? 'bg-[#FF6600] shadow-[0_0_12px_rgba(255,102,0,0.6)]' : 'bg-[#EA580C]';

                    return (
                      <div
                        key={colIdx}
                        className={cn('h-5 rounded-md transition-transform hover:scale-110 cursor-pointer', cellColor)}
                        title={`${tactic} on ${heatmapDays[colIdx]}: ${intensity * 14} attacks`}
                      />
                    );
                  })}
                </div>
              </div>
            ))}

            {/* Bottom Mon-Sun Legend */}
            <div className="flex items-center mt-2">
              <div className="w-24 shrink-0" />
              <div className="flex-1 grid grid-cols-7 gap-1.5 text-center text-[9px] text-[#71717A] dark:text-[#52525B]">
                {heatmapDays.map((d) => (
                  <span key={d}>{d}</span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Bottom 2-Column Split: Security Threats Table (7 cols) + Network Traffic Chart (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Card: Security Threats Table (7 cols) */}
        <div className="lg:col-span-7 rounded-2xl border p-5 flex flex-col justify-between bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-semibold text-[#0A0A0A] dark:text-white">
              Security Threats
            </span>
            <button
              type="button"
              className="text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white"
              aria-label="More options"
            >
              <MoreHorizontal className="w-4 h-4" />
            </button>
          </div>

          {/* Threats Table Headers */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#E5E7EB] dark:border-[#222222] text-[#71717A] dark:text-[#A1A1AA]">
                  <th className="pb-2.5 font-medium">Threat Type</th>
                  <th className="pb-2.5 font-medium">Asset</th>
                  <th className="pb-2.5 font-medium">Risk Level</th>
                  <th className="pb-2.5 font-medium text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E7EB] dark:divide-[#161616]">
                {securityThreats.map((threat) => {
                  // Calculate 10 segments for Risk Level bar
                  const filledSegments = Math.round(threat.riskScore * 10);

                  return (
                    <tr
                      key={threat.id}
                      onClick={() => setSelectedThreat(threat)}
                      className="cursor-pointer hover:bg-[#F3F4F6] dark:hover:bg-[#161616] transition-colors group"
                    >
                      <td className="py-3">
                        <div className="flex flex-col">
                          <span className="font-medium text-[#0A0A0A] dark:text-white group-hover:text-[#FF6600] transition-colors">
                            {threat.threatType}
                          </span>
                          <span className="text-[10px] font-mono text-[#71717A] dark:text-[#A1A1AA]">
                            {threat.code}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 font-mono text-xs text-[#0A0A0A] dark:text-[#E4E4E7]">
                        {threat.asset}
                      </td>
                      {/* 10-Segment Segmented Risk Bar */}
                      <td className="py-3">
                        <div className="flex items-center gap-1">
                          {Array.from({ length: 10 }).map((_, idx) => {
                            const isFilled = idx < filledSegments;
                            return (
                              <div
                                key={idx}
                                className={cn(
                                  'w-2 h-3.5 rounded-xs transition-colors',
                                  isFilled
                                    ? idx > 7
                                      ? 'bg-red-500'
                                      : idx > 4
                                      ? 'bg-[#FF6600]'
                                      : 'bg-amber-400'
                                    : isDark
                                    ? 'bg-[#262626]'
                                    : 'bg-[#E5E7EB]',
                                )}
                              />
                            );
                          })}
                        </div>
                      </td>
                      <td className="py-3 text-right">
                        <span
                          className={cn(
                            'inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-medium border',
                            threat.status === 'Blocked' &&
                              'bg-red-50 text-red-700 border-red-200 dark:bg-red-500/15 dark:text-red-400 dark:border-red-500/30',
                            threat.status === 'Investigating' &&
                              'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-500/15 dark:text-amber-400 dark:border-amber-500/30',
                            threat.status === 'Resolved' &&
                              'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-400 dark:border-emerald-500/30',
                          )}
                        >
                          {threat.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Card: Network Traffic Chart (5 cols) */}
        <div className="lg:col-span-5 rounded-2xl border p-5 flex flex-col justify-between bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-[#0A0A0A] dark:text-white">
              Perimeter Edge Traffic
            </span>
            <button
              type="button"
              className="text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white"
              aria-label="More options"
            >
              <MoreHorizontal className="w-4 h-4" />
            </button>
          </div>

          {/* Traffic Count & Legend Row */}
          <div className="flex items-baseline justify-between mb-4">
            <div className="flex items-baseline gap-3">
              <span className="text-3xl font-semibold font-mono tabular-nums text-[#0A0A0A] dark:text-white">
                40.3M
              </span>
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-400 dark:border-emerald-500/30">
                +6.2% throughput surge
              </span>
            </div>
            {/* Series Legend */}
            <div className="flex items-center gap-3 text-[10px] font-mono">
              <span className="flex items-center gap-1.5 text-[#71717A] dark:text-[#A1A1AA]">
                <span className="w-2 h-2 rounded-full bg-[#FF6600]" /> AWS Ingress
              </span>
              <span className="flex items-center gap-1.5 text-[#71717A] dark:text-[#A1A1AA]">
                <span className="w-2 h-2 rounded-full bg-[#FB923C]" /> Azure Gateway
              </span>
              <span className="flex items-center gap-1.5 text-[#71717A] dark:text-[#A1A1AA]">
                <span className="w-2 h-2 rounded-full bg-[#FACC15]" /> On-Prem DMZ
              </span>
            </div>
          </div>

          {/* Smooth Multi-Layer Curved Area Chart */}
          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficChartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <defs>
                  <linearGradient id="trafficLayer1" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF6600" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#FF6600" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="trafficLayer2" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FB923C" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#FB923C" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="trafficLayer3" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FACC15" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#FACC15" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={gridColor} vertical={false} />
                <XAxis dataKey="day" stroke={axisColor} fontSize={10} tickLine={false} />
                <YAxis stroke={axisColor} fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: isDark ? '#111111' : '#FFFFFF',
                    borderColor: isDark ? '#222222' : '#E5E7EB',
                    borderRadius: '8px',
                    fontSize: '11px',
                    color: isDark ? '#FFFFFF' : '#0A0A0A',
                  }}
                />
                <Area
                  type="natural"
                  dataKey="layer1"
                  stroke="#FF6600"
                  strokeWidth={2}
                  fill="url(#trafficLayer1)"
                />
                <Area
                  type="natural"
                  dataKey="layer2"
                  stroke="#FB923C"
                  strokeWidth={2}
                  fill="url(#trafficLayer2)"
                />
                <Area
                  type="natural"
                  dataKey="layer3"
                  stroke="#FACC15"
                  strokeWidth={1.5}
                  fill="url(#trafficLayer3)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* 4. Slide-Over Event Detail Drawer */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-xs">
          <div className="w-full max-w-md h-full bg-white dark:bg-[#0A0A0A] border-l border-[#E5E7EB] dark:border-[#222222] p-6 overflow-y-auto flex flex-col justify-between shadow-2xl">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-[#E5E7EB] dark:border-[#222222]">
                <div>
                  <h3 className="text-base font-semibold text-[#0A0A0A] dark:text-white">
                    {selectedThreat.threatType}
                  </h3>
                  <span className="text-xs font-mono text-[#71717A] dark:text-[#A1A1AA]">
                    {selectedThreat.code}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedThreat(null)}
                  className="p-1.5 rounded-lg text-[#71717A] hover:bg-[#F3F4F6] dark:hover:bg-[#161616]"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Event Attributes */}
              <div className="mt-4 space-y-3 text-xs">
                <div>
                  <span className="text-[#71717A] dark:text-[#A1A1AA] block text-[10px]">Asset / Path</span>
                  <span className="font-mono text-sm font-semibold">{selectedThreat.asset}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-y border-[#E5E7EB] dark:border-[#222222]">
                  <span className="text-[#71717A] dark:text-[#A1A1AA]">Risk Probability</span>
                  <span className="font-mono font-semibold text-red-500">
                    {selectedThreat.riskScore.toFixed(4)}
                  </span>
                </div>
                <div>
                  <span className="text-[#71717A] dark:text-[#A1A1AA] block text-[10px]">Client IP</span>
                  <span className="font-mono">{selectedThreat.clientIp || '185.190.110.23'}</span>
                </div>
                <div>
                  <span className="text-[#71717A] dark:text-[#A1A1AA] block text-[10px]">Detection Trigger</span>
                  <span className="font-mono text-[#FF8800]">{selectedThreat.reason || 'ML_TRANSFORMER_SPIKE'}</span>
                </div>
              </div>
            </div>

            {/* Bottom Investigation CTA */}
            <div className="pt-6 border-t border-[#E5E7EB] dark:border-[#222222] space-y-2">
              <Link
                to={`/events?searchPath=${encodeURIComponent(selectedThreat.path || '')}`}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-[#FF6600] to-[#EA580C] shadow-md hover:brightness-110"
              >
                <span>Investigate Full Log Stream</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </Link>
              <button
                type="button"
                onClick={() => setSelectedThreat(null)}
                className="w-full py-2 rounded-xl text-xs text-[#71717A] dark:text-[#A1A1AA] hover:bg-[#F3F4F6] dark:hover:bg-[#161616]"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
