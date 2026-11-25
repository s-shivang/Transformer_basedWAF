import { EventFeedback } from './event-feedback.entity';
import { FeedbackQueryParams } from './security-event.types';

export const EVENT_FEEDBACK_REPOSITORY = Symbol('IEventFeedbackRepository');

export interface IEventFeedbackRepository {
  save(feedback: EventFeedback): Promise<void>;
  findById(tenantId: string, feedbackId: string): Promise<EventFeedback | null>;
  findByEventId(tenantId: string, eventId: string): Promise<EventFeedback[]>;
  list(tenantId: string, params: FeedbackQueryParams): Promise<{ items: EventFeedback[]; total: number }>;
  countPending(tenantId: string, siteId?: string): Promise<number>;
}
