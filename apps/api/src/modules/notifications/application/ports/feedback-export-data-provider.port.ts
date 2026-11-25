export interface ApprovedFeedbackRow {
  id: string;
  tenantId: string;
  siteId?: string | null;
  securityEventId: string;
  label: string;
  reviewStatus: string;
  notes?: string | null;
  reviewNotes?: string | null;
  createdAt: Date;
  reviewedAt?: Date | null;
  event?: {
    requestId?: string;
    method?: string;
    path?: string;
    riskScore?: number;
    action?: string;
    stageUsed?: string | null;
  } | null;
}

export interface IFeedbackExportDataProvider {
  getApprovedFeedback(tenantId: string): Promise<ApprovedFeedbackRow[]>;
  recordExportAudit(
    tenantId: string,
    userId: string,
    metadata: {
      recordCount: number;
      sha256Digest: string;
      exportedAt: string;
    },
  ): Promise<void>;
}

export const FEEDBACK_EXPORT_DATA_PROVIDER = 'FEEDBACK_EXPORT_DATA_PROVIDER';
