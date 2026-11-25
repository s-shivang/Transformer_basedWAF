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
} from 'lucide-react';

export const FeedbackPage: React.FC = () => {
  const { canReviewFeedback } = useAuth();
  const queryClient = useQueryClient();
  const [selectedStatus, setSelectedStatus] = useState<string>('PENDING_REVIEW');
  const [reviewModalItem, setReviewModalItem] = useState<{
    id: string;
    action: 'APPROVED' | 'REJECTED';
    notes: string;
  } | null>(null);

  const { data: feedbackList, isLoading, error } = useQuery({
    queryKey: ['feedback', selectedStatus],
    queryFn: () =>
      api.feedback.list(selectedStatus === 'ALL' ? {} : { status: selectedStatus }),
  });

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
      setReviewModalItem(null);
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
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/10 text-amber-500 border border-amber-500/20">
            <Clock className="w-3 h-3" /> Pending Review
          </span>
        );
      case 'APPROVED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3" /> Approved for Dataset
          </span>
        );
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-rose-500/10 text-rose-500 border border-rose-500/20">
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

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#0A0A0A] dark:text-white flex items-center gap-2">
          <MessageSquare className="w-6 h-6 text-[#FF6600]" />
          <span>False-Positive Feedback Queue</span>
        </h1>
        <p className="text-sm text-[#71717A] dark:text-[#A1A1AA] mt-1">
          Review analyst feedback on flagged requests and curate high-confidence samples for the offline ML retraining pipeline.
        </p>
      </div>

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

      {/* Status Filter Tabs */}
      <div className="flex border-b border-[#E5E7EB] dark:border-[#222222] space-x-4">
        {[
          { id: 'PENDING_REVIEW', label: 'Pending Review' },
          { id: 'APPROVED', label: 'Approved' },
          { id: 'REJECTED', label: 'Rejected' },
          { id: 'ALL', label: 'All Submissions' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setSelectedStatus(tab.id)}
            className={`pb-3 text-xs font-medium border-b-2 transition-colors ${
              selectedStatus === tab.id
                ? 'border-[#FF6600] text-[#FF6600] dark:text-[#FF8800] font-semibold'
                : 'border-transparent text-[#71717A] hover:text-[#0A0A0A] dark:text-[#A1A1AA] dark:hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
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
        ) : !feedbackList || feedbackList.length === 0 ? (
          <div className="p-12 text-center">
            <FileCheck className="w-12 h-12 text-[#71717A] dark:text-[#A1A1AA] mx-auto mb-3" />
            <h3 className="text-base font-medium text-[#0A0A0A] dark:text-zinc-200">
              No feedback entries found
            </h3>
            <p className="text-sm text-[#71717A] dark:text-[#A1A1AA] mt-1">
              There are currently no submissions with status "{selectedStatus}".
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-[#71717A] dark:text-[#A1A1AA]">
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
                {feedbackList.map((item: any) => (
                  <tr
                    key={item.id}
                    className="hover:bg-[#F3F4F6] dark:hover:bg-[#161616] transition-colors"
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      {getStatusBadge(item.status)}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-medium text-[#0A0A0A] dark:text-white">
                      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-[#FF6600]/10 text-[#FF6600] dark:text-[#FF8800] border border-[#FF6600]/20">
                        {item.label}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-mono text-xs text-[#0A0A0A] dark:text-zinc-100">
                        {item.event?.method || 'N/A'} {item.event?.path || 'N/A'}
                      </div>
                      <div className="text-xs text-[#71717A] dark:text-[#A1A1AA] font-mono">
                        {item.event?.requestId || item.eventId}
                      </div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap w-44">
                      {item.event?.riskScore !== undefined ? (
                        <RiskMeter score={item.event.riskScore} />
                      ) : (
                        <span className="text-xs text-[#71717A] dark:text-[#A1A1AA]">N/A</span>
                      )}
                    </td>
                    <td className="py-3 px-4 max-w-xs">
                      <div className="text-xs text-[#0A0A0A] dark:text-zinc-300 line-clamp-2">
                        {item.notes || <span className="italic text-[#71717A] dark:text-[#A1A1AA]">No notes provided</span>}
                      </div>
                      {item.reviewNotes && (
                        <div className="text-xs text-[#71717A] dark:text-[#A1A1AA] mt-1 italic">
                          Reviewer: {item.reviewNotes}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-xs text-[#71717A] dark:text-[#A1A1AA]">
                      {new Date(item.createdAt).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap text-right">
                      {canReviewFeedback && item.status === 'PENDING_REVIEW' ? (
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() =>
                              setReviewModalItem({
                                id: item.id,
                                action: 'APPROVED',
                                notes: '',
                              })
                            }
                            className="px-2.5 py-1 text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20 border border-emerald-500/30 transition-colors"
                          >
                            Approve
                          </button>
                          <button
                            onClick={() =>
                              setReviewModalItem({
                                id: item.id,
                                action: 'REJECTED',
                                notes: '',
                              })
                            }
                            className="px-2.5 py-1 text-xs font-medium rounded-lg bg-rose-500/10 text-rose-500 hover:bg-rose-500/20 border border-rose-500/30 transition-colors"
                          >
                            Reject
                          </button>
                        </div>
                      ) : (
                        <span className="text-xs text-[#71717A] dark:text-[#A1A1AA]">
                          {item.status === 'PENDING_REVIEW' ? 'Review restricted' : 'Completed'}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
                  className="w-full px-3 py-2 text-sm rounded-xl bg-[#F9FAFB] dark:bg-[#111111] border border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600] focus:border-[#FF6600]"
                  placeholder="e.g., Validated legitimate enterprise webhook query parameters."
                />
              </div>

              {reviewMutation.isError && (
                <div className="p-3 text-xs rounded-xl bg-red-500/10 text-red-500 border border-red-500/20">
                  {(reviewMutation.error as Error).message}
                </div>
              )}

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setReviewModalItem(null)}
                  className="px-4 py-2 text-sm font-medium rounded-xl text-[#71717A] dark:text-[#A1A1AA] hover:bg-[#F3F4F6] dark:hover:bg-[#161616]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={reviewMutation.isPending}
                  className={`px-4 py-2 text-sm font-semibold rounded-xl text-white ${
                    reviewModalItem.action === 'APPROVED'
                      ? 'bg-emerald-600 hover:bg-emerald-500'
                      : 'bg-rose-600 hover:bg-rose-500'
                  } disabled:opacity-50`}
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
    </div>
  );
};
