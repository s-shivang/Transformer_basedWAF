export enum WafAction {
  ALLOW = 'ALLOW',
  MONITOR = 'MONITOR',
  CHALLENGE = 'CHALLENGE',
  BLOCK = 'BLOCK',
}

export enum FeedbackLabel {
  FALSE_POSITIVE = 'FALSE_POSITIVE',
  CONFIRMED_ATTACK = 'CONFIRMED_ATTACK',
  SUSPICIOUS = 'SUSPICIOUS',
  NEEDS_INVESTIGATION = 'NEEDS_INVESTIGATION',
}

export enum FeedbackReviewStatus {
  PENDING_REVIEW = 'PENDING_REVIEW',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
}

export enum SecuritySeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export interface SecurityEventQueryParams {
  siteId?: string;
  action?: WafAction;
  minRiskScore?: number;
  maxRiskScore?: number;
  stageUsed?: string;
  degradedMode?: boolean;
  from?: Date;
  to?: Date;
  pathContains?: string;
  page?: number;
  limit?: number;
}

export interface FeedbackQueryParams {
  siteId?: string;
  reviewStatus?: FeedbackReviewStatus;
  label?: FeedbackLabel;
  page?: number;
  limit?: number;
}
