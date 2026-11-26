import { Inject, Injectable, Optional } from '@nestjs/common';
import { IJobQueue } from '@shared/infrastructure/queues/job-queue.interface';
import { JOB_QUEUE_TOKEN, QUEUES, JOBS } from '@shared/infrastructure/queues/queue.constants';
import { Result } from '@shared/application/result';
import { SecurityEvent } from '../domain/security-event.entity';
import { EventFeedback } from '../domain/event-feedback.entity';
import {
  ISecurityEventRepository,
  SECURITY_EVENT_REPOSITORY,
} from '../domain/security-event.repository.interface';
import {
  IEventFeedbackRepository,
  EVENT_FEEDBACK_REPOSITORY,
} from '../domain/event-feedback.repository.interface';
import {
  IProtectedSiteRepository,
  PROTECTED_SITE_REPOSITORY,
} from '../../protected-sites/domain/protected-site.repository.interface';
import {
  IAuditLogRepository,
  AUDIT_LOG_REPOSITORY,
} from '../../identity/domain/identity.repository.interfaces';
import { AuditLog } from '../../identity/domain/audit-log.entity';
import { IngestSecurityEventDto } from '../presentation/dtos/ingest-event.dto';
import { QuerySecurityEventsDto } from '../presentation/dtos/security-event-query.dto';
import {
  SubmitFeedbackDto,
  ReviewFeedbackDto,
  QueryFeedbackDto,
} from '../presentation/dtos/feedback.dto';
import { FeedbackReviewStatus } from '../domain/security-event.types';

export function serializeSecurityEvent(event: SecurityEvent) {
  return {
    id: event.id,
    tenantId: event.tenantId,
    siteId: event.siteId,
    requestId: event.requestId,
    clientIpHash: event.clientIpHash,
    method: event.method,
    path: event.path,
    action: event.action,
    wouldAction: event.wouldAction,
    reason: event.reason,
    riskScore: event.riskScore,
    severity: event.severity,
    stageUsed: event.stageUsed,
    ruleMatches: event.ruleMatches,
    anomalyFlags: event.anomalyFlags,
    degradedMode: event.degradedMode,
    modelVersion: event.modelVersion,
    policyVersion: event.policyVersion,
    latencyMs: event.latencyMs,
    redactedRequest: event.redactedRequest,
    createdAt: event.createdAt.toISOString(),
  };
}

export function serializeEventFeedback(feedback: EventFeedback) {
  return {
    id: feedback.id,
    tenantId: feedback.tenantId,
    siteId: feedback.siteId,
    securityEventId: feedback.securityEventId,
    submittedByUserId: feedback.submittedByUserId,
    label: feedback.label,
    reviewStatus: feedback.reviewStatus,
    reviewerUserId: feedback.reviewerUserId,
    notes: feedback.notes,
    reviewNotes: feedback.reviewNotes,
    createdAt: feedback.createdAt.toISOString(),
    reviewedAt: feedback.reviewedAt ? feedback.reviewedAt.toISOString() : null,
  };
}

@Injectable()
export class IngestSecurityEventsUseCase {
  constructor(
    @Inject(SECURITY_EVENT_REPOSITORY) private readonly eventRepo: ISecurityEventRepository,
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Optional() @Inject(JOB_QUEUE_TOKEN) private readonly jobQueue?: IJobQueue,
  ) {}

  async execute(eventsDto: IngestSecurityEventDto[]): Promise<Result<{ ingested: number; ids: string[] }>> {
    if (!eventsDto || eventsDto.length === 0) {
      return Result.fail('No events provided for ingestion');
    }

    if (eventsDto.length > 100) {
      return Result.fail('Batch ingestion limit exceeded (maximum 100 events per request)');
    }

    const domainEvents: SecurityEvent[] = [];

    for (const dto of eventsDto) {
      // Validate site belongs to tenant if siteId provided
      if (dto.siteId) {
        const site = await this.siteRepo.findById(dto.tenantId, dto.siteId);
        if (!site) {
          return Result.fail(`Protected site '${dto.siteId}' not found for tenant '${dto.tenantId}'`);
        }
      }

      const eventRes = SecurityEvent.create({
        tenantId: dto.tenantId,
        siteId: dto.siteId,
        requestId: dto.requestId,
        clientIpHash: dto.clientIpHash,
        method: dto.method,
        path: dto.path,
        action: dto.action,
        wouldAction: dto.wouldAction,
        reason: dto.reason,
        riskScore: dto.riskScore,
        stageUsed: dto.stageUsed,
        ruleMatches: dto.ruleMatches,
        anomalyFlags: dto.anomalyFlags,
        degradedMode: dto.degradedMode,
        modelVersion: dto.modelVersion,
        policyVersion: dto.policyVersion,
        latencyMs: dto.latencyMs,
        redactedRequest: dto.redactedRequest,
        createdAt: dto.createdAt ? new Date(dto.createdAt) : new Date(),
      });

      if (eventRes.isFailure) {
        return Result.fail(`Invalid event '${dto.requestId}': ${eventRes.getError()}`);
      }

      domainEvents.push(eventRes.getValue());
    }

    await this.eventRepo.saveBatch(domainEvents);

    // Asynchronously enqueue alerts evaluation
    if (this.jobQueue) {
      const eventsByTenant = new Map<string, IngestSecurityEventDto[]>();
      for (const dto of eventsDto) {
        if (!eventsByTenant.has(dto.tenantId)) {
          eventsByTenant.set(dto.tenantId, []);
        }
        eventsByTenant.get(dto.tenantId)!.push(dto);
      }

      for (const [tenantId, tenantEvents] of eventsByTenant.entries()) {
        await this.jobQueue.enqueue(QUEUES.ALERTS, JOBS.PROCESS_ALERTS, {
          tenantId,
          events: tenantEvents.map((e) => ({
            siteId: e.siteId,
            action: e.action,
            degradedMode: e.degradedMode,
            path: e.path,
            requestId: e.requestId,
          })),
        });
      }
    }

    return Result.ok({
      ingested: domainEvents.length,
      ids: domainEvents.map((e) => e.id),
    });
  }
}

@Injectable()
export class QuerySecurityEventsUseCase {
  constructor(
    @Inject(SECURITY_EVENT_REPOSITORY) private readonly eventRepo: ISecurityEventRepository,
  ) {}

  async execute(tenantId: string, dto: QuerySecurityEventsDto): Promise<Result<any>> {
    const page = Math.max(1, dto.page ?? 1);
    const limit = Math.min(100, Math.max(1, dto.limit ?? 20));

    const fromDate = dto.from ? new Date(dto.from) : undefined;
    const toDate = dto.to ? new Date(dto.to) : undefined;

    const { items, total } = await this.eventRepo.query(tenantId, {
      siteId: dto.siteId,
      action: dto.action,
      minRiskScore: dto.minRiskScore,
      maxRiskScore: dto.maxRiskScore,
      stageUsed: dto.stageUsed,
      degradedMode: dto.degradedMode,
      pathContains: dto.pathContains,
      from: fromDate,
      to: toDate,
      page,
      limit,
    });

    return Result.ok({
      items: items.map(serializeSecurityEvent),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  }
}

@Injectable()
export class GetSecurityEventByIdUseCase {
  constructor(
    @Inject(SECURITY_EVENT_REPOSITORY) private readonly eventRepo: ISecurityEventRepository,
  ) {}

  async execute(tenantId: string, eventId: string): Promise<Result<any>> {
    const event = await this.eventRepo.findById(tenantId, eventId);
    if (!event) {
      return Result.fail(`Security event '${eventId}' not found`);
    }

    return Result.ok(serializeSecurityEvent(event));
  }
}

@Injectable()
export class SubmitEventFeedbackUseCase {
  constructor(
    @Inject(SECURITY_EVENT_REPOSITORY) private readonly eventRepo: ISecurityEventRepository,
    @Inject(EVENT_FEEDBACK_REPOSITORY) private readonly feedbackRepo: IEventFeedbackRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(
    tenantId: string,
    eventId: string,
    dto: SubmitFeedbackDto,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<any>> {
    const event = await this.eventRepo.findById(tenantId, eventId);
    if (!event) {
      return Result.fail(`Security event '${eventId}' not found`);
    }

    const feedbackRes = EventFeedback.create({
      tenantId,
      siteId: event.siteId,
      securityEventId: event.id,
      submittedByUserId: userId,
      label: dto.label,
      notes: dto.notes,
    });

    if (feedbackRes.isFailure) {
      return Result.fail(feedbackRes.getError());
    }

    const feedback = feedbackRes.getValue();
    await this.feedbackRepo.save(feedback);

    // Audit log
    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'EVENT_FEEDBACK_SUBMITTED',
      resource: 'EventFeedback',
      resourceId: feedback.id,
      metadata: {
        eventId,
        label: feedback.label,
        reviewStatus: feedback.reviewStatus,
      },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok(serializeEventFeedback(feedback));
  }
}

@Injectable()
export class ListFeedbackQueueUseCase {
  constructor(
    @Inject(EVENT_FEEDBACK_REPOSITORY) private readonly feedbackRepo: IEventFeedbackRepository,
  ) {}

  async execute(tenantId: string, dto: QueryFeedbackDto): Promise<Result<any>> {
    const page = Math.max(1, dto.page ?? 1);
    const limit = Math.min(100, Math.max(1, dto.limit ?? 20));

    const reviewStatus = dto.reviewStatus || dto.status;

    const { items, total } = await this.feedbackRepo.list(tenantId, {
      siteId: dto.siteId,
      reviewStatus,
      label: dto.label,
      page,
      limit,
    });

    return Result.ok({
      items: items.map(serializeEventFeedback),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    });
  }
}

@Injectable()
export class ReviewEventFeedbackUseCase {
  constructor(
    @Inject(EVENT_FEEDBACK_REPOSITORY) private readonly feedbackRepo: IEventFeedbackRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(
    tenantId: string,
    feedbackId: string,
    dto: ReviewFeedbackDto,
    reviewerUserId: string,
    clientIp?: string,
  ): Promise<Result<any>> {
    const feedback = await this.feedbackRepo.findById(tenantId, feedbackId);
    if (!feedback) {
      return Result.fail(`Event feedback '${feedbackId}' not found`);
    }

    let transitionRes: Result<void>;
    if (dto.status === FeedbackReviewStatus.APPROVED) {
      transitionRes = feedback.approve(reviewerUserId, dto.reviewNotes);
    } else if (dto.status === FeedbackReviewStatus.REJECTED) {
      transitionRes = feedback.reject(reviewerUserId, dto.reviewNotes);
    } else {
      return Result.fail(`Invalid target review status '${dto.status}' (must be APPROVED or REJECTED)`);
    }

    if (transitionRes.isFailure) {
      return Result.fail(transitionRes.getError());
    }

    await this.feedbackRepo.save(feedback);

    // Audit log
    const audit = AuditLog.create({
      tenantId,
      userId: reviewerUserId,
      action: 'EVENT_FEEDBACK_REVIEWED',
      resource: 'EventFeedback',
      resourceId: feedback.id,
      metadata: {
        newStatus: feedback.reviewStatus,
        reviewerUserId,
        reviewNotes: feedback.reviewNotes,
      },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok(serializeEventFeedback(feedback));
  }
}
