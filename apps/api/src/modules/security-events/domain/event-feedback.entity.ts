import { Entity } from '@shared/domain/entity.base';
import { Result } from '@shared/application/result';
import { FeedbackLabel, FeedbackReviewStatus } from './security-event.types';

export interface EventFeedbackProps {
  tenantId: string;
  siteId?: string | null;
  securityEventId: string;
  submittedByUserId?: string | null;
  label: FeedbackLabel;
  reviewStatus: FeedbackReviewStatus;
  reviewerUserId?: string | null;
  notes?: string | null;
  reviewNotes?: string | null;
  createdAt: Date;
  reviewedAt?: Date | null;
}

export class EventFeedback extends Entity<string> {
  private _props: EventFeedbackProps;

  private constructor(id: string, props: EventFeedbackProps) {
    super(id);
    this._props = props;
  }

  get tenantId(): string {
    return this._props.tenantId;
  }

  get siteId(): string | null {
    return this._props.siteId ?? null;
  }

  get securityEventId(): string {
    return this._props.securityEventId;
  }

  get submittedByUserId(): string | null {
    return this._props.submittedByUserId ?? null;
  }

  get label(): FeedbackLabel {
    return this._props.label;
  }

  get reviewStatus(): FeedbackReviewStatus {
    return this._props.reviewStatus;
  }

  get reviewerUserId(): string | null {
    return this._props.reviewerUserId ?? null;
  }

  get notes(): string | null {
    return this._props.notes ?? null;
  }

  get reviewNotes(): string | null {
    return this._props.reviewNotes ?? null;
  }

  get createdAt(): Date {
    return this._props.createdAt;
  }

  get reviewedAt(): Date | null {
    return this._props.reviewedAt ?? null;
  }

  public approve(reviewerUserId: string, reviewNotes?: string): Result<void> {
    if (this._props.reviewStatus !== FeedbackReviewStatus.PENDING_REVIEW) {
      return Result.fail(`Cannot approve feedback with status '${this._props.reviewStatus}' (must be PENDING_REVIEW)`);
    }

    if (!reviewerUserId || typeof reviewerUserId !== 'string') {
      return Result.fail('reviewerUserId is required to approve feedback');
    }

    this._props.reviewStatus = FeedbackReviewStatus.APPROVED;
    this._props.reviewerUserId = reviewerUserId;
    this._props.reviewNotes = reviewNotes?.trim() ?? null;
    this._props.reviewedAt = new Date();

    return Result.ok();
  }

  public reject(reviewerUserId: string, reviewNotes?: string): Result<void> {
    if (this._props.reviewStatus !== FeedbackReviewStatus.PENDING_REVIEW) {
      return Result.fail(`Cannot reject feedback with status '${this._props.reviewStatus}' (must be PENDING_REVIEW)`);
    }

    if (!reviewerUserId || typeof reviewerUserId !== 'string') {
      return Result.fail('reviewerUserId is required to reject feedback');
    }

    this._props.reviewStatus = FeedbackReviewStatus.REJECTED;
    this._props.reviewerUserId = reviewerUserId;
    this._props.reviewNotes = reviewNotes?.trim() ?? null;
    this._props.reviewedAt = new Date();

    return Result.ok();
  }

  public static create(props: {
    id?: string;
    tenantId: string;
    siteId?: string | null;
    securityEventId: string;
    submittedByUserId?: string | null;
    label: FeedbackLabel;
    notes?: string | null;
    createdAt?: Date;
  }): Result<EventFeedback> {
    if (!props.tenantId || typeof props.tenantId !== 'string') {
      return Result.fail<EventFeedback>('tenantId is required');
    }

    if (!props.securityEventId || typeof props.securityEventId !== 'string') {
      return Result.fail<EventFeedback>('securityEventId is required');
    }

    if (!props.label || !Object.values(FeedbackLabel).includes(props.label)) {
      return Result.fail<EventFeedback>('Valid feedback label is required');
    }

    return Result.ok<EventFeedback>(
      new EventFeedback(props.id ?? crypto.randomUUID(), {
        tenantId: props.tenantId,
        siteId: props.siteId ?? null,
        securityEventId: props.securityEventId,
        submittedByUserId: props.submittedByUserId ?? null,
        label: props.label,
        reviewStatus: FeedbackReviewStatus.PENDING_REVIEW,
        reviewerUserId: null,
        notes: props.notes?.trim() ?? null,
        reviewNotes: null,
        createdAt: props.createdAt ?? new Date(),
        reviewedAt: null,
      }),
    );
  }

  public static reconstitute(id: string, props: EventFeedbackProps): EventFeedback {
    return new EventFeedback(id, props);
  }
}
