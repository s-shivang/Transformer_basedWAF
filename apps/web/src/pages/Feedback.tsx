import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { RiskMeter } from '../components/common/RiskMeter';
import {
  MessageSquare,
  CheckCircle2,
  XCircle,
  Clock,
  Info,
  Filter,
  AlertTriangle,
  FileCheck,
  ShieldAlert,
  Download,
  Database,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  Eye,
  RefreshCw,
  Search,
} from 'lucide-react';
import { cn } from '../lib/utils';

export const FeedbackPage: React.FC = () => {
  const { user, canReviewFeedback } = useAuth();
  const queryClient = useQueryClient();
  const [selectedStatus, setSelectedStatus] = useState<string>('PENDING_REVIEW');
  const [page, setPage] = useState<number>(1);
  const [selectedLabel, setSelectedLabel] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Review modal state
  const [reviewModalItem, setReviewModalItem] = useState<{
    id: string;
    action: 'APPROVED' | 'REJECTED';
    notes: string;
  } | null>(null);

  // Detail drawer state
  const [inspectItem, setInspectItem] = useState<any | null>(null);

  // Export success state
  const [exportNotice, setExportNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const isAdminOrOwner = user?.role === 'OWNER' || user?.role === 'ADMIN';

  // Fetch feedback queue items
  const { data: feedbackResponse, isLoading, error, refetch } = useQuery({
    queryKey: ['feedback', selectedStatus, selectedLabel, page],
    queryFn: () =>
      api.feedback.list({
        reviewStatus: selectedStatus === 'ALL' ? undefined : selectedStatus,
        status: selectedStatus === 'ALL' ? undefined : selectedStatus,
        label: selectedLabel === 'ALL' ? undefined : selectedLabel,
        page,
        limit: 15,
      }),
  });

  // Extract items and pagination
  const feedbackList: any[] = Array.isArray(feedbackResponse)
    ? feedbackResponse
    : feedbackResponse?.items || [];
  const totalItems: number = feedbackResponse?.total ?? feedbackList.length;
  const totalPages: number = feedbackResponse?.totalPages ?? Math.max(1, Math.ceil(totalItems / 15));

  // Review mutation
  const reviewMutation = useMutation({
    mutationFn: ({
      feedbackId,
      status,
      reviewNotes,
    }: {
      feedbackId: string;
      status: string;
      reviewNotes?: string;
    }) => api.feedback.review(feedbackId, { status, reviewNotes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['feedback'] });
      queryClient.invalidateQueries({ queryKey: ['feedback-pending-count'] });
      setReviewModalItem(null);
      if (inspectItem) {
        setInspectItem(null);
      }
    },
  });

  // Export dataset mutation
  const exportMutation = useMutation({
    mutationFn: () => api.feedback.exportDataset(),
    onSuccess: (data) => {
      setExportNotice({
        type: 'success',
        message: `Offline ML dataset export queued successfully (Job: ${data.jobId}). You will receive an in-app notification when ready.`,
      });
      setTimeout(() => setExportNotice(null), 6000);
    },
    onError: (err: any) => {
      setExportNotice({
        type: 'error',
        message: err.message || 'Failed to trigger dataset export.',
      });
      setTimeout(() => setExportNotice(null), 6000);
    },
  });

  const handleReviewSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!reviewModalItem) return;
    reviewMutation.mutate({
      feedbackId: reviewModalItem.id,
      status: reviewModalItem.action,
      reviewNotes: reviewModalItem.notes || undefined,
    });
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'PENDING_REVIEW':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-500 border border-amber-500/20">
            <Clock className="w-3 h-3" /> Pending Review
          </span>
        );
      case 'APPROVED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3" /> Approved for Dataset
          </span>
        );
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-500 border border-rose-500/20">
            <XCircle className="w-3 h-3" /> Rejected
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-zinc-500/10 text-zinc-400">
            {status}
          </span>
        );
    }
  };

  const getLabelBadge = (label: string) => {
    switch (label) {
      case 'FALSE_POSITIVE':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-[#FF6600]/10 text-[#FF6600] dark:text-[#FF8800] border border-[#FF6600]/20">
            FALSE POSITIVE
          </span>
        );
      case 'CONFIRMED_ATTACK':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-500/10 text-red-500 border border-red-500/20">
            CONFIRMED ATTACK
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">
            SUSPICIOUS
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-zinc-500/10 text-zinc-400">
            {label}
          </span>
        );
    }
  };

  // Local filter for search box
  const filteredList = feedbackList.filter((item: any) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    const path = item.event?.path?.toLowerCase() || '';
    const notes = item.notes?.toLowerCase() || '';
    const reqId = (item.event?.requestId || item.securityEventId || '').toLowerCase();
    return path.includes(q) || notes.includes(q) || reqId.includes(q);
  });

  return (
    <div className="space-y-6">
      {/* Page Header with Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#0A0A0A] dark:text-white flex items-center gap-2">
            <MessageSquare className="w-6 h-6 text-[#FF6600]" />
            <span>False-Positive Feedback Queue</span>
          </h1>
          <p className="text-sm text-[#71717A] dark:text-[#A1A1AA] mt-1">
            Review analyst feedback on flagged requests and curate high-confidence samples for the offline ML retraining pipeline.
          </p>
        </div>

        {isAdminOrOwner && (
          <button
            type="button"
            onClick={() => exportMutation.mutate()}
            disabled={exportMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 shadow-md transition-all disabled:opacity-50"
            title="Export approved feedback to S3/offline ML dataset"
          >
            <Download className={cn('w-4 h-4', exportMutation.isPending && 'animate-spin')} />
            <span>{exportMutation.isPending ? 'Exporting...' : 'Export Curated Dataset'}</span>
          </button>
        )}
      </div>

      {/* Export Feedback Notice */}
      {exportNotice && (
        <div
          className={cn(
            'p-3.5 rounded-2xl border text-xs flex items-center gap-2.5 transition-all',
            exportNotice.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 dark:text-emerald-400'
              : 'bg-rose-500/10 border-rose-500/20 text-rose-600 dark:text-rose-400',
          )}
        >
          {exportNotice.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-500" />
          ) : (
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-500" />
          )}
          <span>{exportNotice.message}</span>
        </div>
      )}

      {/* Safety Notice Banner */}
      <div className="rounded-2xl border border-[#FF6600]/30 bg-[#FFF7ED]/50 dark:bg-[#161616] p-4 text-[#0A0A0A] dark:text-white">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-[#FF6600] shrink-0 mt-0.5" />
          <div className="text-xs">
            <span className="font-semibold text-[#FF6600] dark:text-[#FF8800]">
              ML Safety & Governance Protocol:
            </span>{' '}
            Marking an event as a False Positive never mutates live production weights or active thresholds automatically.
            Approved entries are indexed into a locked feedback dataset for isolated offline validation and batch model evaluation.
          </div>
        </div>
      </div>

      {/* Filter Toolbar: Status Tabs + Label Filter + Search Box */}
      <div className="p-3.5 rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] flex flex-wrap items-center justify-between gap-3 shadow-sm">
        {/* Status Tabs */}
        <div className="flex items-center gap-1.5">
          {[
            { id: 'PENDING_REVIEW', label: 'Pending Review' },
            { id: 'APPROVED', label: 'Approved' },
            { id: 'REJECTED', label: 'Rejected' },
            { id: 'ALL', label: 'All Submissions' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                setSelectedStatus(tab.id);
                setPage(1);
              }}
              className={cn(
                'px-3 py-1.5 rounded-xl text-xs font-semibold transition-all',
                selectedStatus === tab.id
                  ? 'bg-[#FF6600] text-white shadow-sm'
                  : 'text-[#71717A] dark:text-[#A1A1AA] hover:bg-zinc-100 dark:hover:bg-[#1A1A1A] hover:text-[#0A0A0A] dark:hover:text-white',
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Search & Label Filters */}
        <div className="flex items-center gap-2">
          {/* Label selector */}
          <select
            value={selectedLabel}
            onChange={(e) => {
              setSelectedLabel(e.target.value);
              setPage(1);
            }}
            className="px-3 py-1.5 text-xs rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
          >
            <option value="ALL">All Classifications</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="CONFIRMED_ATTACK">Confirmed Attack</option>
            <option value="SUSPICIOUS">Suspicious</option>
          </select>

          {/* Quick Filter Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[#71717A] absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search path or notes..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-xs rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
            />
          </div>
        </div>
      </div>

      {/* Feedback List Table */}
      <div className="rounded-2xl border border-[#E5E7EB] dark:border-[#222222] bg-white dark:bg-[#0A0A0A] overflow-hidden shadow-sm">
        {isLoading ? (
          <div className="p-12 text-center text-[#71717A] dark:text-[#A1A1AA] animate-pulse">
            Loading feedback submissions...
          </div>
        ) : error ? (
          <div className="p-8 text-center text-rose-500">
            Failed to load feedback queue: {(error as Error).message}
          </div>
        ) : filteredList.length === 0 ? (
          <div className="p-12 text-center">
            <FileCheck className="w-12 h-12 text-[#71717A] dark:text-[#A1A1AA] mx-auto mb-3" />
            <h3 className="text-base font-semibold text-[#0A0A0A] dark:text-zinc-200">
              No feedback entries found
            </h3>
            <p className="text-sm text-[#71717A] dark:text-[#A1A1AA] mt-1">
              There are currently no submissions matching the selected filters.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-[#F9FAFB]/50 dark:bg-[#111111]/50 text-xs uppercase tracking-wider text-[#71717A] dark:text-[#A1A1AA] font-semibold border-b border-[#E5E7EB] dark:border-[#222222]">
                <tr>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">Event Path / Method</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Analyst Notes</th>
                  <th className="py-3 px-4">Submitted At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E7EB] dark:divide-[#222222]">
                {filteredList.map((item: any) => {
                  const currentStatus = item.reviewStatus || item.status;
                  const isPending = currentStatus === 'PENDING_REVIEW';

                  return (
                    <tr
                      key={item.id}
                      className="hover:bg-[#F3F4F6] dark:hover:bg-[#161616] transition-colors"
                    >
                      <td className="py-3 px-4 whitespace-nowrap">
                        {getStatusBadge(currentStatus)}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {getLabelBadge(item.label)}
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-mono text-xs text-[#0A0A0A] dark:text-zinc-100 font-medium">
                          {item.event?.method || 'N/A'} {item.event?.path || 'N/A'}
                        </div>
                        <div className="text-[11px] text-[#71717A] dark:text-[#A1A1AA] font-mono">
                          {item.event?.requestId || item.securityEventId}
                        </div>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap w-44">
                        {item.event?.riskScore !== undefined ? (
                          <RiskMeter score={item.event.riskScore} />
                        ) : (
                          <span className="text-xs text-[#71717A] dark:text-[#A1A1AA] font-mono">N/A</span>
                        )}
                      </td>
                      <td className="py-3 px-4 max-w-xs">
                        <div className="text-xs text-[#0A0A0A] dark:text-zinc-300 line-clamp-2">
                          {item.notes || <span className="italic text-[#71717A] dark:text-[#A1A1AA]">No notes provided</span>}
                        </div>
                        {item.reviewNotes && (
                          <div className="text-[11px] text-[#71717A] dark:text-[#A1A1AA] mt-1 italic">
                            Reviewer: {item.reviewNotes}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap font-mono text-xs text-[#71717A] dark:text-[#A1A1AA]">
                        {new Date(item.createdAt).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* Inspect drawer button */}
                          <button
                            type="button"
                            onClick={() => setInspectItem(item)}
                            className="p-1.5 rounded-lg text-[#71717A] hover:text-[#0A0A0A] dark:text-[#A1A1AA] dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-[#1F1F1F]"
                            title="Inspect Payload & Context"
                          >
                            <Eye className="w-4 h-4" />
                          </button>

                          {/* Approve / Reject actions for SOC Reviewers */}
                          {canReviewFeedback && isPending ? (
                            <>
                              <button
                                type="button"
                                onClick={() =>
                                  setReviewModalItem({
                                    id: item.id,
                                    action: 'APPROVED',
                                    notes: '',
                                  })
                                }
                                className="px-2.5 py-1 text-xs font-semibold rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 transition-colors"
                              >
                                Approve
                              </button>
                              <button
                                type="button"
                                onClick={() =>
                                  setReviewModalItem({
                                    id: item.id,
                                    action: 'REJECTED',
                                    notes: '',
                                  })
                                }
                                className="px-2.5 py-1 text-xs font-semibold rounded-lg bg-rose-500/10 text-rose-600 dark:text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 transition-colors"
                              >
                                Reject
                              </button>
                            </>
                          ) : (
                            <span className="text-xs text-[#71717A] dark:text-[#A1A1AA]">
                              {isPending ? 'Review restricted' : 'Completed'}
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div className="p-3.5 border-t border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/50 dark:bg-[#111111]/50 flex items-center justify-between text-xs text-[#71717A] dark:text-[#A1A1AA]">
            <span>
              Showing {filteredList.length} of {totalItems} entries
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="p-1 rounded hover:bg-zinc-200 dark:hover:bg-zinc-800 disabled:opacity-30"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="font-mono">
                Page {page} of {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="p-1 rounded hover:bg-zinc-200 dark:hover:bg-zinc-800 disabled:opacity-30"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Review Modal */}
      {reviewModalItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl bg-white dark:bg-[#0A0A0A] border border-[#E5E7EB] dark:border-[#222222] p-6 shadow-2xl">
            <h3 className="text-lg font-bold text-[#0A0A0A] dark:text-white flex items-center gap-2">
              {reviewModalItem.action === 'APPROVED' ? (
                <>
                  <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                  Approve Feedback Submission
                </>
              ) : (
                <>
                  <XCircle className="w-5 h-5 text-rose-500" />
                  Reject Feedback Submission
                </>
              )}
            </h3>
            <p className="text-xs text-[#71717A] dark:text-[#A1A1AA] mt-2">
              {reviewModalItem.action === 'APPROVED'
                ? 'Approving marks this request payload as high-confidence ground truth for dataset curation.'
                : 'Rejecting marks this feedback submission as invalid or unverified.'}
            </p>

            <form onSubmit={handleReviewSubmit} className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-[#71717A] dark:text-[#A1A1AA] mb-1">
                  Reviewer Notes (Optional)
                </label>
                <textarea
                  value={reviewModalItem.notes}
                  onChange={(e) =>
                    setReviewModalItem({ ...reviewModalItem, notes: e.target.value })
                  }
                  rows={3}
                  className="w-full px-3 py-2 text-xs rounded-xl bg-[#F9FAFB] dark:bg-[#111111] border border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
                  placeholder="e.g., Validated legitimate enterprise webhook query parameters."
                />
              </div>

              {reviewMutation.isError && (
                <div className="p-3 text-xs rounded-xl bg-rose-500/10 text-rose-500 border border-rose-500/20">
                  {(reviewMutation.error as Error).message}
                </div>
              )}

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setReviewModalItem(null)}
                  className="px-4 py-2 text-xs font-medium rounded-xl text-[#71717A] dark:text-[#A1A1AA] hover:bg-[#F3F4F6] dark:hover:bg-[#161616]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={reviewMutation.isPending}
                  className={cn(
                    'px-4 py-2 text-xs font-semibold rounded-xl text-white disabled:opacity-50',
                    reviewModalItem.action === 'APPROVED'
                      ? 'bg-emerald-600 hover:bg-emerald-500'
                      : 'bg-rose-600 hover:bg-rose-500',
                  )}
                >
                  {reviewMutation.isPending
                    ? 'Submitting...'
                    : reviewModalItem.action === 'APPROVED'
                    ? 'Confirm Approval'
                    : 'Confirm Rejection'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Inspect Item Details Modal / Drawer */}
      {inspectItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-2xl bg-white dark:bg-[#0A0A0A] rounded-2xl border border-[#E5E7EB] dark:border-[#222222] p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-[#E5E7EB] dark:border-[#222222]">
              <div>
                <h3 className="text-base font-bold text-[#0A0A0A] dark:text-white flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-[#FF6600]" />
                  <span>Feedback Submission Inspection</span>
                </h3>
                <p className="text-xs text-[#71717A] dark:text-[#A1A1AA] mt-0.5 font-mono">
                  Feedback ID: {inspectItem.id}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setInspectItem(null)}
                className="px-2.5 py-1 text-xs rounded-lg border border-[#E5E7EB] dark:border-[#222222] text-[#71717A] hover:bg-zinc-100 dark:hover:bg-zinc-800"
              >
                Close
              </button>
            </div>

            {/* Event Overview */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
              <div className="p-3 rounded-xl bg-zinc-50 dark:bg-[#111111] border border-[#E5E7EB] dark:border-[#222222]">
                <span className="text-[#71717A]">Classification:</span>
                <div className="mt-1">{getLabelBadge(inspectItem.label)}</div>
              </div>
              <div className="p-3 rounded-xl bg-zinc-50 dark:bg-[#111111] border border-[#E5E7EB] dark:border-[#222222]">
                <span className="text-[#71717A]">Review Status:</span>
                <div className="mt-1">{getStatusBadge(inspectItem.reviewStatus || inspectItem.status)}</div>
              </div>
              <div className="p-3 rounded-xl bg-zinc-50 dark:bg-[#111111] border border-[#E5E7EB] dark:border-[#222222]">
                <span className="text-[#71717A]">Associated Event:</span>
                <div className="mt-1 font-mono font-bold text-[#FF6600]">
                  {inspectItem.event?.method || 'N/A'} {inspectItem.event?.path || 'N/A'}
                </div>
              </div>
            </div>

            {/* Analyst & Reviewer Notes */}
            <div className="space-y-2 text-xs">
              <div className="p-3 rounded-xl bg-zinc-50 dark:bg-[#111111] border border-[#E5E7EB] dark:border-[#222222]">
                <span className="text-[#71717A] font-semibold">Analyst Justification / Notes:</span>
                <p className="mt-1 text-[#0A0A0A] dark:text-zinc-200">
                  {inspectItem.notes || 'No notes provided by submitting analyst.'}
                </p>
              </div>

              {inspectItem.reviewNotes && (
                <div className="p-3 rounded-xl bg-purple-500/5 border border-purple-500/20">
                  <span className="text-purple-600 dark:text-purple-400 font-semibold">Reviewer Audit Notes:</span>
                  <p className="mt-1 text-[#0A0A0A] dark:text-zinc-200">{inspectItem.reviewNotes}</p>
                </div>
              )}
            </div>

            {/* Event Telemetry Details */}
            {inspectItem.event && (
              <div className="space-y-2 text-xs">
                <span className="font-semibold text-[#71717A]">Underlying Event Telemetry:</span>
                <div className="p-3 rounded-xl bg-[#0F0F0F] text-zinc-300 font-mono text-[11px] space-y-1.5 border border-zinc-800">
                  <div>Request ID: {inspectItem.event.requestId}</div>
                  <div>Action: {inspectItem.event.action}</div>
                  <div>Risk Score: {inspectItem.event.riskScore}</div>
                  <div>Inspection Reason: {inspectItem.event.reason || 'N/A'}</div>
                  <div>Model Version: {inspectItem.event.modelVersion || 'v1.0.0'}</div>
                </div>
              </div>
            )}

            {/* Footer with Approve / Reject action if still pending */}
            <div className="flex items-center justify-between pt-2 border-t border-[#E5E7EB] dark:border-[#222222]">
              <span className="text-xs text-[#71717A]">
                Submitted: {new Date(inspectItem.createdAt).toLocaleString()}
              </span>

              {canReviewFeedback && (inspectItem.reviewStatus === 'PENDING_REVIEW' || inspectItem.status === 'PENDING_REVIEW') && (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setReviewModalItem({ id: inspectItem.id, action: 'APPROVED', notes: '' });
                    }}
                    className="px-3 py-1.5 text-xs font-semibold rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white"
                  >
                    Approve
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setReviewModalItem({ id: inspectItem.id, action: 'REJECTED', notes: '' });
                    }}
                    className="px-3 py-1.5 text-xs font-semibold rounded-xl bg-rose-600 hover:bg-rose-500 text-white"
                  >
                    Reject
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
