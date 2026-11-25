import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Search,
  Filter,
  X,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Send,
  AlertCircle,
  CheckCircle2,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { ActionBadge } from '../components/common/ActionBadge';
import { RiskMeter } from '../components/common/RiskMeter';
import { cn } from '../lib/utils';

export const Events: React.FC = () => {
  const { selectedSiteId, canSubmitFeedback } = useAuth();
  const queryClient = useQueryClient();

  const [actionFilter, setActionFilter] = useState<string>('ALL');
  const [searchPath, setSearchPath] = useState<string>('');
  const [minScore, setMinScore] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);

  // Feedback form state
  const [feedbackLabel, setFeedbackLabel] = useState<string>('FALSE_POSITIVE');
  const [feedbackNotes, setFeedbackNotes] = useState<string>('');
  const [feedbackStatusMsg, setFeedbackStatusMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const { data: eventsData, isLoading } = useQuery({
    queryKey: ['events', selectedSiteId, actionFilter, searchPath, minScore, page],
    queryFn: () =>
      api.events.query({
        siteId: selectedSiteId || undefined,
        action: actionFilter !== 'ALL' ? actionFilter : undefined,
        pathContains: searchPath || undefined,
        minRiskScore: minScore ? parseFloat(minScore) : undefined,
        page,
        limit: 20,
      }),
  });

  const submitFeedbackMutation = useMutation({
    mutationFn: (data: { eventId: string; label: string; notes?: string }) =>
      api.events.submitFeedback(data.eventId, { label: data.label, notes: data.notes }),
    onSuccess: () => {
      setFeedbackStatusMsg({
        type: 'success',
        text: 'Feedback successfully queued for human review. Live ML weights remain untouched.',
      });
      setFeedbackNotes('');
      queryClient.invalidateQueries({ queryKey: ['feedback-pending-count'] });
    },
    onError: (err: any) => {
      setFeedbackStatusMsg({
        type: 'error',
        text: err.message || 'Failed to submit feedback.',
      });
    },
  });

  const handleOpenDrawer = (event: any) => {
    setSelectedEvent(event);
    setFeedbackStatusMsg(null);
    setFeedbackNotes('');
  };

  const handleFeedbackSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedEvent) return;
    setFeedbackStatusMsg(null);
    submitFeedbackMutation.mutate({
      eventId: selectedEvent.id,
      label: feedbackLabel,
      notes: feedbackNotes,
    });
  };

  const actions = ['ALL', 'BLOCK', 'CHALLENGE', 'MONITOR', 'ALLOW'];
  const items = eventsData?.items || [];
  const total = eventsData?.total || 0;
  const totalPages = eventsData?.totalPages || 1;

  return (
    <div className="space-y-4">
      {/* Page Title */}
      <div>
        <h1 className="text-xl font-bold tracking-tight">Security Events Explorer</h1>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Inspect, filter, and audit deep inspection telemetry across all protected routes
        </p>
      </div>

      {/* Filter Toolbar */}
      <div className="p-3.5 rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] flex flex-wrap items-center justify-between gap-3 shadow-sm">
        {/* Action Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto">
          {actions.map((act) => (
            <button
              key={act}
              type="button"
              onClick={() => {
                setActionFilter(act);
                setPage(1);
              }}
              className={cn(
                'px-2.5 py-1 text-xs font-mono font-medium rounded-xl transition-all border',
                actionFilter === act
                  ? 'bg-gradient-to-r from-[#FF6600] to-[#EA580C] text-white border-transparent shadow-[0_0_10px_rgba(255,102,0,0.3)]'
                  : 'bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white',
              )}
            >
              {act}
            </button>
          ))}
        </div>

        {/* Search & Risk Inputs */}
        <div className="flex items-center gap-2.5 flex-1 max-w-md">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-[#71717A] dark:text-[#A1A1AA] absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              placeholder="Search path (e.g. /login, /search)..."
              value={searchPath}
              onChange={(e) => {
                setSearchPath(e.target.value);
                setPage(1);
              }}
              className="w-full pl-9 pr-3 py-1.5 text-xs font-mono rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white placeholder-[#71717A] focus:outline-none focus:ring-1 focus:ring-[#FF6600] focus:border-[#FF6600]"
            />
          </div>

          <div className="w-28">
            <input
              type="number"
              step="0.05"
              min="0"
              max="1"
              placeholder="Min Risk"
              value={minScore}
              onChange={(e) => {
                setMinScore(e.target.value);
                setPage(1);
              }}
              className="w-full px-2.5 py-1.5 text-xs font-mono rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>
      </div>

      {/* Dense Monospace Events Table */}
      <div className="rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/50 dark:bg-[#111111]/50 text-[#71717A] dark:text-[#A1A1AA] font-medium">
                <th className="py-2.5 px-4 font-mono">Timestamp</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3 font-mono">Method & Path</th>
                <th className="py-2.5 px-3 font-mono text-right">Risk Score</th>
                <th className="py-2.5 px-3 font-mono">Stage</th>
                <th className="py-2.5 px-3 font-mono text-right">Latency</th>
                <th className="py-2.5 px-4">Trigger Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E7EB] dark:divide-[#222222]">
              {items.length > 0 ? (
                items.map((event: any) => (
                  <tr
                    key={event.id}
                    onClick={() => handleOpenDrawer(event)}
                    className={cn(
                      'cursor-pointer transition-colors hover:bg-[#F3F4F6] dark:hover:bg-[#161616]',
                      selectedEvent?.id === event.id && 'bg-[#FFF7ED] dark:bg-[#1C1C1C]',
                    )}
                  >
                    <td className="py-2 px-4 font-mono text-slate-500 whitespace-nowrap">
                      {event.createdAt ? new Date(event.createdAt).toLocaleTimeString([], { hour12: false }) : '-'}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <ActionBadge action={event.action} />
                    </td>
                    <td className="py-2 px-3 font-mono">
                      <span className="font-semibold text-slate-700 dark:text-slate-300 mr-2">
                        {event.method}
                      </span>
                      <span className="text-slate-800 dark:text-slate-200">{event.path}</span>
                    </td>
                    <td className="py-2 px-3 font-mono font-bold tabular-nums text-right">
                      <span
                        className={cn(
                          event.riskScore >= 0.85
                            ? 'text-red-600 dark:text-red-400'
                            : event.riskScore >= 0.50
                              ? 'text-amber-600 dark:text-amber-400'
                              : event.riskScore >= 0.05
                                ? 'text-cyan-600 dark:text-cyan-400'
                                : 'text-emerald-600 dark:text-emerald-400',
                        )}
                      >
                        {event.riskScore.toFixed(4)}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {event.stageUsed || 'l1_rules'}
                    </td>
                    <td className="py-2 px-3 font-mono tabular-nums text-right text-slate-500 whitespace-nowrap">
                      {event.latencyMs?.toFixed(1)} ms
                    </td>
                    <td className="py-2 px-4 text-slate-600 dark:text-slate-400 max-w-[280px] truncate">
                      {event.reason || 'Normal benign request'}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    {isLoading ? 'Loading events telemetry...' : 'No security events match criteria.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-3 border-t border-slate-200 dark:border-[#1F2937] flex items-center justify-between text-xs text-slate-500">
          <span>
            Total events: <strong className="font-mono text-slate-800 dark:text-slate-200">{total}</strong>
          </span>
          <div className="flex items-center gap-2">
            <span>
              Page <strong className="font-mono">{page}</strong> of <strong className="font-mono">{totalPages}</strong>
            </span>
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
              className="p-1 rounded border border-slate-200 dark:border-[#1F2937] disabled:opacity-30 hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              type="button"
              disabled={page >= totalPages}
              onClick={() => setPage(page + 1)}
              className="p-1 rounded border border-slate-200 dark:border-[#1F2937] disabled:opacity-30 hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Right Slide-Over Inspection Drawer */}
      {selectedEvent && (
        <div className="fixed inset-y-0 right-0 w-full sm:w-[500px] z-50 bg-white dark:bg-[#0A0A0A] border-l border-[#E5E7EB] dark:border-[#222222] shadow-2xl flex flex-col overflow-hidden animate-in slide-in-from-right duration-200">
          {/* Drawer Header */}
          <div className="p-4 border-b border-[#E5E7EB] dark:border-[#222222] flex items-center justify-between bg-[#F9FAFB]/50 dark:bg-[#111111]/50">
            <div className="flex items-center gap-2.5">
              <ActionBadge action={selectedEvent.action} />
              <span className="font-mono font-semibold text-xs text-[#0A0A0A] dark:text-white truncate">
                {selectedEvent.requestId}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setSelectedEvent(null)}
              className="p-1 rounded text-[#71717A] hover:text-[#0A0A0A] dark:text-[#A1A1AA] dark:hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Drawer Scrollable Content */}
          <div className="flex-1 overflow-y-auto p-5 space-y-6">
            {/* Visual Risk Score Meter */}
            <div className="p-3.5 rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222]">
              <RiskMeter score={selectedEvent.riskScore} />
            </div>

            {/* HTTP Request Monospace Summary */}
            <div className="space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">Request Target</span>
              <div className="p-3 rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] font-mono text-xs break-all">
                <span className="text-blue-600 dark:text-blue-400 font-bold mr-2">{selectedEvent.method}</span>
                <span className="text-slate-800 dark:text-slate-100">{selectedEvent.path}</span>
              </div>
            </div>

            {/* Detection Telemetry Metadata Grid */}
            <div className="space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">Detection Context</span>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono p-3 rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937]">
                <div>
                  <span className="text-slate-400 block text-[10px]">STAGE USED</span>
                  <span className="font-semibold">{selectedEvent.stageUsed || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">MODEL VERSION</span>
                  <span className="font-semibold">{selectedEvent.modelVersion || 'v1_0'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">POLICY VERSION</span>
                  <span className="font-semibold">v{selectedEvent.policyVersion || 1}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">DEGRADED MODE</span>
                  <span className={selectedEvent.degradedMode ? 'text-amber-500 font-bold' : 'text-slate-300'}>
                    {selectedEvent.degradedMode ? 'TRUE' : 'FALSE'}
                  </span>
                </div>
              </div>
            </div>

            {/* Redacted Monospace Request JSON */}
            <div className="space-y-1.5">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                Redacted Payload (Privacy-Safe)
              </span>
              <pre className="p-3 rounded-lg border bg-slate-900 text-slate-100 border-slate-800 font-mono text-[11px] overflow-x-auto max-h-48 leading-relaxed">
                {JSON.stringify(selectedEvent.redactedRequest || { note: 'No payload captured' }, null, 2)}
              </pre>
            </div>

            {/* False-Positive Submission Section (Hidden for VIEWER) */}
            {canSubmitFeedback && (
              <div className="pt-2 border-t border-slate-200 dark:border-[#1F2937]">
                <h3 className="text-xs font-bold text-slate-800 dark:text-slate-200 mb-1 flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-amber-500" />
                  <span>Submit Security Feedback</span>
                </h3>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mb-3">
                  Report False Positives or Confirmed Attacks to the supervisory human review queue.
                </p>

                {feedbackStatusMsg && (
                  <div
                    className={cn(
                      'p-2.5 rounded-lg text-xs mb-3 flex items-center gap-2 border',
                      feedbackStatusMsg.type === 'success'
                        ? 'bg-emerald-50 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30'
                        : 'bg-red-50 text-red-800 dark:bg-red-500/15 dark:text-red-400 border-red-200 dark:border-red-500/30',
                    )}
                  >
                    {feedbackStatusMsg.type === 'success' ? (
                      <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
                    ) : (
                      <AlertCircle className="w-4 h-4 shrink-0 text-red-600" />
                    )}
                    <span>{feedbackStatusMsg.text}</span>
                  </div>
                )}

                <form onSubmit={handleFeedbackSubmit} className="space-y-3">
                  <div>
                    <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
                      Feedback Label
                    </label>
                    <select
                      value={feedbackLabel}
                      onChange={(e) => setFeedbackLabel(e.target.value)}
                      className="w-full text-xs font-mono rounded-lg border p-2 bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-800 dark:text-slate-200"
                    >
                      <option value="FALSE_POSITIVE">FALSE_POSITIVE (Harmless Traffic Blocked)</option>
                      <option value="CONFIRMED_ATTACK">CONFIRMED_ATTACK (Actual Threat Detected)</option>
                      <option value="SUSPICIOUS">SUSPICIOUS (Requires Further Triage)</option>
                      <option value="NEEDS_INVESTIGATION">NEEDS_INVESTIGATION</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
                      Analyst Notes (Optional)
                    </label>
                    <textarea
                      rows={2}
                      value={feedbackNotes}
                      onChange={(e) => setFeedbackNotes(e.target.value)}
                      placeholder="Why is this a False Positive? e.g. legitimate SQL keywords in search query..."
                      className="w-full text-xs rounded-lg border p-2 bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={submitFeedbackMutation.isPending}
                    className="w-full py-2.5 px-3 rounded-xl bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 text-white font-medium text-xs flex items-center justify-center gap-1.5 transition-all shadow-[0_0_15px_rgba(255,102,0,0.3)] disabled:opacity-50"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>{submitFeedbackMutation.isPending ? 'Submitting...' : 'Queue for Human Review'}</span>
                  </button>
                </form>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
