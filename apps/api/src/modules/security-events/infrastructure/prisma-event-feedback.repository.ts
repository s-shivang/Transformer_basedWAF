import { Injectable } from '@nestjs/common';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import { EventFeedback } from '../domain/event-feedback.entity';
import {
  FeedbackLabel,
  FeedbackReviewStatus,
  FeedbackQueryParams,
} from '../domain/security-event.types';
import { IEventFeedbackRepository } from '../domain/event-feedback.repository.interface';

@Injectable()
export class PrismaEventFeedbackRepository implements IEventFeedbackRepository {
  constructor(private readonly prisma: PrismaService) {}

  async save(feedback: EventFeedback): Promise<void> {
    await this.prisma.eventFeedback.upsert({
      where: { id: feedback.id },
      create: {
        id: feedback.id,
        tenantId: feedback.tenantId,
        siteId: feedback.siteId,
        securityEventId: feedback.securityEventId,
        submittedByUserId: feedback.submittedByUserId,
        label: feedback.label as any,
        reviewStatus: feedback.reviewStatus as any,
        reviewerUserId: feedback.reviewerUserId,
        notes: feedback.notes,
        reviewNotes: feedback.reviewNotes,
        createdAt: feedback.createdAt,
        reviewedAt: feedback.reviewedAt,
      },
      update: {
        reviewStatus: feedback.reviewStatus as any,
        reviewerUserId: feedback.reviewerUserId,
        reviewNotes: feedback.reviewNotes,
        reviewedAt: feedback.reviewedAt,
      },
    });
  }

  async findById(tenantId: string, feedbackId: string): Promise<EventFeedback | null> {
    const record = await this.prisma.eventFeedback.findFirst({
      where: { id: feedbackId, tenantId },
    });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findByEventId(tenantId: string, eventId: string): Promise<EventFeedback[]> {
    const records = await this.prisma.eventFeedback.findMany({
      where: { tenantId, securityEventId: eventId },
      orderBy: { createdAt: 'desc' },
    });
    return records.map((r) => this.toDomain(r));
  }

  async list(
    tenantId: string,
    params: FeedbackQueryParams,
  ): Promise<{ items: EventFeedback[]; total: number }> {
    const where: any = { tenantId };

    if (params.siteId) where.siteId = params.siteId;
    if (params.reviewStatus) where.reviewStatus = params.reviewStatus;
    if (params.label) where.label = params.label;

    const page = Math.max(1, params.page ?? 1);
    const limit = Math.min(100, Math.max(1, params.limit ?? 20));
    const skip = (page - 1) * limit;

    const [records, total] = await Promise.all([
      this.prisma.eventFeedback.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.eventFeedback.count({ where }),
    ]);

    return {
      items: records.map((r) => this.toDomain(r)),
      total,
    };
  }

  async countPending(tenantId: string, siteId?: string): Promise<number> {
    const where: any = { tenantId, reviewStatus: FeedbackReviewStatus.PENDING_REVIEW };
    if (siteId) where.siteId = siteId;
    return this.prisma.eventFeedback.count({ where });
  }

  private toDomain(record: any): EventFeedback {
    return EventFeedback.reconstitute(record.id, {
      tenantId: record.tenantId,
      siteId: record.siteId,
      securityEventId: record.securityEventId,
      submittedByUserId: record.submittedByUserId,
      label: record.label as FeedbackLabel,
      reviewStatus: record.reviewStatus as FeedbackReviewStatus,
      reviewerUserId: record.reviewerUserId,
      notes: record.notes,
      reviewNotes: record.reviewNotes,
      createdAt: record.createdAt,
      reviewedAt: record.reviewedAt,
    });
  }
}
