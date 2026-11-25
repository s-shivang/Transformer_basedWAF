import { EventFeedback } from '../domain/event-feedback.entity';
import { FeedbackQueryParams } from '../domain/security-event.types';
import { IEventFeedbackRepository } from '../domain/event-feedback.repository.interface';

export class InMemoryEventFeedbackRepository implements IEventFeedbackRepository {
  private feedbacks: Map<string, EventFeedback> = new Map();

  async save(feedback: EventFeedback): Promise<void> {
    this.feedbacks.set(feedback.id, feedback);
  }

  async findById(tenantId: string, feedbackId: string): Promise<EventFeedback | null> {
    const fb = this.feedbacks.get(feedbackId);
    if (fb && fb.tenantId === tenantId) {
      return fb;
    }
    return null;
  }

  async findByEventId(tenantId: string, eventId: string): Promise<EventFeedback[]> {
    return Array.from(this.feedbacks.values())
      .filter((fb) => fb.tenantId === tenantId && fb.securityEventId === eventId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async list(
    tenantId: string,
    params: FeedbackQueryParams,
  ): Promise<{ items: EventFeedback[]; total: number }> {
    let matches = Array.from(this.feedbacks.values()).filter((fb) => fb.tenantId === tenantId);

    if (params.siteId) {
      matches = matches.filter((fb) => fb.siteId === params.siteId);
    }
    if (params.reviewStatus) {
      matches = matches.filter((fb) => fb.reviewStatus === params.reviewStatus);
    }
    if (params.label) {
      matches = matches.filter((fb) => fb.label === params.label);
    }

    matches.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    const total = matches.length;
    const page = Math.max(1, params.page ?? 1);
    const limit = Math.min(100, Math.max(1, params.limit ?? 20));
    const offset = (page - 1) * limit;

    const items = matches.slice(offset, offset + limit);
    return { items, total };
  }

  async countPending(tenantId: string, siteId?: string): Promise<number> {
    return Array.from(this.feedbacks.values()).filter((fb) => {
      if (fb.tenantId !== tenantId) return false;
      if (siteId && fb.siteId !== siteId) return false;
      return fb.reviewStatus === 'PENDING_REVIEW';
    }).length;
  }

  clear(): void {
    this.feedbacks.clear();
  }
}
