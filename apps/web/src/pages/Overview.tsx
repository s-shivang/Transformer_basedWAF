import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ShieldAlert,
  ShieldCheck,
  Clock,
  MessageSquareWarning,
  ArrowUpRight,
  Activity,
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
import { ActionBadge } from '../components/common/ActionBadge';
import { Link } from 'react-router-dom';

export const Overview: React.FC = () => {
  const { selectedSiteId, timeWindow } = useAuth();
  const { theme } = useTheme();

  // 1. Overview KPIs
  const { data: overviewData, isLoading: loadingOverview } = useQuery({
    queryKey: ['analytics-overview', selectedSiteId, timeWindow],
    queryFn: () => api.analytics.overview({ siteId: selectedSiteId || undefined, window: timeWindow }),
  });

  // 2. Timeseries traffic
  const { data: timeseriesData, isLoading: loadingTimeseries } = useQuery({
    queryKey: ['analytics-timeseries', selectedSiteId, timeWindow],
    queryFn: () => api.analytics.timeseries({ siteId: selectedSiteId || undefined, window: timeWindow }),
  });

  // 3. Top threats
  const { data: threatsData } = useQuery({
    queryKey: ['analytics-top-threats', selectedSiteId, timeWindow],
    queryFn: () => api.analytics.topThreats({ siteId: selectedSiteId || undefined, window: timeWindow, limit: 5 }),
  });

  // 4. Recent high-risk events
  const { data: eventsData } = useQuery({
    queryKey: ['recent-events', selectedSiteId],
    queryFn: () => api.events.query({ siteId: selectedSiteId || undefined, limit: 6, minRiskScore: 0.50 }),
  });

  const metrics = overviewData?.metrics || {
    totalRequests: 0,
    blockedCount: 0,
    challengedCount: 0,
    monitoredCount: 0,
    allowedCount: 0,
    blockRatePct: 0.0,
    avgLatencyMs: 0.0,
    p50LatencyMs: 0.0,
    p95LatencyMs: 0.0,
    pendingFalsePositivesCount: 0,
  };

  const chartData = (timeseriesData?.buckets || []).map((b: any) => ({
    time: b.bucket.includes('T') ? b.bucket.split('T')[1].slice(0, 5) : b.bucket.slice(5),
    allowed: b.allowed,
    monitored: b.monitored,
    challenged: b.challenged,
    blocked: b.blocked,
  }));

  const isDark = theme === 'dark';
  const gridColor = isDark ? '#1F2937' : '#E2E8F0';
  const axisColor = isDark ? '#94A3B8' : '#64748B';
  const tooltipBg = isDark ? '#111827' : '#FFFFFF';
  const tooltipBorder = isDark ? '#1F2937' : '#E2E8F0';

  const blockedChallengedPct =
    metrics.totalRequests > 0
      ? Math.round(((metrics.blockedCount + metrics.challengedCount) / metrics.totalRequests) * 10000) / 100
      : 0;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Security Overview</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Real-time multi-layer threat telemetry and automated traffic mitigation
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-slate-500 dark:text-slate-400">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>ML Pipeline Active</span>
        </div>
      </div>

      {/* Row 1: KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Requests */}
        <div className="p-4 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-medium">Total Requests</span>
            <Activity className="w-4 h-4 text-blue-500" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums">
            {metrics.totalRequests.toLocaleString()}
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 flex items-center gap-1.5">
            <span className="text-emerald-600 dark:text-emerald-400 font-mono font-medium">
              {metrics.allowedCount} allowed
            </span>
            <span>•</span>
            <span className="text-cyan-600 dark:text-cyan-400 font-mono font-medium">
              {metrics.monitoredCount} monitored
            </span>
          </div>
        </div>

        {/* Blocked & Challenged % */}
        <div className="p-4 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-medium">Blocked & Challenged</span>
            <ShieldAlert className="w-4 h-4 text-red-500" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-red-600 dark:text-red-400">
            {blockedChallengedPct}%
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 flex items-center gap-1.5">
            <span className="font-mono text-red-600 dark:text-red-400 font-medium">
              {metrics.blockedCount} blocked
            </span>
            <span>•</span>
            <span className="font-mono text-amber-600 dark:text-amber-400 font-medium">
              {metrics.challengedCount} challenged
            </span>
          </div>
        </div>

        {/* p95 Latency */}
        <div className="p-4 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-medium">p95 Latency</span>
            <Clock className="w-4 h-4 text-cyan-500" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums">
            {metrics.p95LatencyMs.toFixed(2)}{' '}
            <span className="text-sm font-normal text-slate-400 font-sans">ms</span>
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            p50: <span className="font-mono">{metrics.p50LatencyMs.toFixed(2)} ms</span> • avg:{' '}
            <span className="font-mono">{metrics.avgLatencyMs.toFixed(2)} ms</span>
          </div>
        </div>

        {/* Pending False Positives */}
        <Link
          to="/feedback"
          className="p-4 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs hover:border-blue-400 dark:hover:border-blue-500/50 transition-colors group block"
        >
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-medium">Pending Feedback</span>
            <MessageSquareWarning className="w-4 h-4 text-amber-500 group-hover:translate-x-0.5 transition-transform" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-amber-600 dark:text-amber-400">
            {metrics.pendingFalsePositivesCount}
          </div>
          <div className="text-xs text-blue-600 dark:text-blue-400 mt-1 flex items-center gap-1 font-medium">
            <span>Review feedback queue</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </div>
        </Link>
      </div>

      {/* Row 2: Recharts Stacked Area Traffic Chart */}
      <div className="p-5 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold tracking-tight">Traffic Volume & Action Distribution</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Stacked traffic telemetry categorized by WAF data plane decision
            </p>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <span className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-[#10B981]" /> Allowed
            </span>
            <span className="flex items-center gap-1.5 text-cyan-600 dark:text-cyan-400">
              <span className="w-2 h-2 rounded-full bg-[#06B6D4]" /> Monitored
            </span>
            <span className="flex items-center gap-1.5 text-amber-600 dark:text-amber-400">
              <span className="w-2 h-2 rounded-full bg-[#F59E0B]" /> Challenged
            </span>
            <span className="flex items-center gap-1.5 text-red-600 dark:text-red-400">
              <span className="w-2 h-2 rounded-full bg-[#EF4444]" /> Blocked
            </span>
          </div>
        </div>

        {chartData.length > 0 ? (
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10B981" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorMonitored" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorChallenged" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#F59E0B" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={gridColor} vertical={false} />
                <XAxis dataKey="time" stroke={axisColor} fontSize={11} tickLine={false} />
                <YAxis stroke={axisColor} fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: tooltipBg,
                    borderColor: tooltipBorder,
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: isDark ? '#F8FAFC' : '#0F172A',
                    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="allowed"
                  stackId="1"
                  stroke="#10B981"
                  fill="url(#colorAllowed)"
                />
                <Area
                  type="monotone"
                  dataKey="monitored"
                  stackId="1"
                  stroke="#06B6D4"
                  fill="url(#colorMonitored)"
                />
                <Area
                  type="monotone"
                  dataKey="challenged"
                  stackId="1"
                  stroke="#F59E0B"
                  fill="url(#colorChallenged)"
                />
                <Area
                  type="monotone"
                  dataKey="blocked"
                  stackId="1"
                  stroke="#EF4444"
                  fill="url(#colorBlocked)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-64 flex flex-col items-center justify-center text-center p-6 border border-dashed rounded-lg border-slate-200 dark:border-[#1F2937]">
            <ShieldCheck className="w-10 h-10 text-slate-300 dark:text-slate-600 mb-2" />
            <span className="text-sm font-medium text-slate-600 dark:text-slate-300">
              No traffic telemetry recorded yet for this window
            </span>
            <span className="text-xs text-slate-400 mt-0.5">
              Traffic passing through the Python WAF data plane will populate here in real-time.
            </span>
          </div>
        )}
      </div>

      {/* Row 3: Bottom Split — Top Attacked Paths & Recent High-Risk Events */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Attacked Paths */}
        <div className="p-5 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs">
          <h2 className="text-sm font-semibold tracking-tight mb-1">Top Targeted Endpoints</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
            Most targeted URI paths ranked by frequency and block counts
          </p>

          {(threatsData?.topPaths || []).length > 0 ? (
            <div className="space-y-3">
              {(threatsData?.topPaths || []).map((tp: any, idx: number) => (
                <div key={idx} className="flex flex-col gap-1 text-xs">
                  <div className="flex justify-between items-center">
                    <span className="font-mono text-slate-800 dark:text-slate-200 truncate max-w-[280px]">
                      {tp.path}
                    </span>
                    <span className="font-mono text-slate-500 dark:text-slate-400 shrink-0">
                      <span className="text-red-600 dark:text-red-400 font-semibold">
                        {tp.blockedCount} blocked
                      </span>{' '}
                      / {tp.count} reqs
                    </span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-red-500 rounded-full"
                      style={{
                        width: `${Math.min(100, Math.max(8, (tp.count / (threatsData.topPaths[0].count || 1)) * 100))}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-400">
              Zero threat endpoints detected in this window.
            </div>
          )}
        </div>

        {/* Recent High-Risk Events Monospace List */}
        <div className="p-5 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold tracking-tight">Recent High-Risk Detections</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Security events scoring in the Challenge (0.50+) or Block (0.85+) band
              </p>
            </div>
            <Link
              to="/events"
              className="text-xs text-blue-600 dark:text-blue-400 font-medium hover:underline flex items-center gap-1"
            >
              <span>View all</span>
              <ArrowUpRight className="w-3 h-3" />
            </Link>
          </div>

          {(eventsData?.items || []).length > 0 ? (
            <div className="divide-y divide-slate-100 dark:divide-[#1F2937]">
              {(eventsData?.items || []).map((e: any) => (
                <div key={e.id} className="py-2.5 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2.5 overflow-hidden">
                    <ActionBadge action={e.action} />
                    <span className="font-mono font-medium text-slate-700 dark:text-slate-300">
                      {e.method}
                    </span>
                    <span className="font-mono text-slate-600 dark:text-slate-400 truncate max-w-[200px]">
                      {e.path}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                      {e.riskScore.toFixed(4)}
                    </span>
                    <span className="font-mono text-[11px] text-slate-400">
                      {e.createdAt ? new Date(e.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-400">
              No recent high-risk events recorded.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
