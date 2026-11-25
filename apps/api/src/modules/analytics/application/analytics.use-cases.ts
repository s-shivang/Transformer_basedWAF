import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import {
  ISecurityEventRepository,
  SECURITY_EVENT_REPOSITORY,
} from '../../security-events/domain/security-event.repository.interface';
import {
  IEventFeedbackRepository,
  EVENT_FEEDBACK_REPOSITORY,
} from '../../security-events/domain/event-feedback.repository.interface';
import {
  IProtectedSiteRepository,
  PROTECTED_SITE_REPOSITORY,
} from '../../protected-sites/domain/protected-site.repository.interface';
import {
  computeOverviewMetrics,
  computeTimeseriesBuckets,
  computeTopThreats,
} from '../domain/analytics-calculator';
import { AnalyticsWindow, QueryAnalyticsDto } from '../presentation/dtos/analytics-query.dto';

function calculateWindowFrom(window: AnalyticsWindow = AnalyticsWindow.HOURS_24): Date {
  const now = new Date();
  if (window === AnalyticsWindow.DAYS_30) {
    return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  }
  if (window === AnalyticsWindow.DAYS_7) {
    return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  }
  // Default 24h
  return new Date(now.getTime() - 24 * 60 * 60 * 1000);
}

@Injectable()
export class GetAnalyticsOverviewUseCase {
  constructor(
    @Inject(SECURITY_EVENT_REPOSITORY) private readonly eventRepo: ISecurityEventRepository,
    @Inject(EVENT_FEEDBACK_REPOSITORY) private readonly feedbackRepo: IEventFeedbackRepository,
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
  ) {}

  async execute(tenantId: string, dto: QueryAnalyticsDto): Promise<Result<any>> {
    if (dto.siteId) {
      const site = await this.siteRepo.findById(tenantId, dto.siteId);
      if (!site) {
        return Result.fail(`Protected site '${dto.siteId}' not found for tenant`);
      }
    }

    const fromDate = calculateWindowFrom(dto.window);
    const events = await this.eventRepo.findRawForAnalytics(tenantId, {
      siteId: dto.siteId,
      from: fromDate,
    });

    const pendingFeedbacks = await this.feedbackRepo.countPending(tenantId, dto.siteId);

    const metrics = computeOverviewMetrics(events, pendingFeedbacks);

    return Result.ok({
      window: dto.window ?? AnalyticsWindow.HOURS_24,
      siteId: dto.siteId ?? null,
      from: fromDate.toISOString(),
      to: new Date().toISOString(),
      metrics,
    });
  }
}

@Injectable()
export class GetAnalyticsTimeseriesUseCase {
  constructor(
    @Inject(SECURITY_EVENT_REPOSITORY) private readonly eventRepo: ISecurityEventRepository,
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
  ) {}

  async execute(tenantId: string, dto: QueryAnalyticsDto): Promise<Result<any>> {
    if (dto.siteId) {
      const site = await this.siteRepo.findById(tenantId, dto.siteId);
      if (!site) {
        return Result.fail(`Protected site '${dto.siteId}' not found for tenant`);
      }
    }

    const window = dto.window ?? AnalyticsWindow.HOURS_24;
    const fromDate = calculateWindowFrom(window);
    const events = await this.eventRepo.findRawForAnalytics(tenantId, {
      siteId: dto.siteId,
      from: fromDate,
    });

    const buckets = computeTimeseriesBuckets(events, window);

    return Result.ok({
      window,
      siteId: dto.siteId ?? null,
      from: fromDate.toISOString(),
      to: new Date().toISOString(),
      buckets,
    });
  }
}

@Injectable()
export class GetTopThreatsUseCase {
  constructor(
    @Inject(SECURITY_EVENT_REPOSITORY) private readonly eventRepo: ISecurityEventRepository,
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
  ) {}

  async execute(tenantId: string, dto: QueryAnalyticsDto): Promise<Result<any>> {
    if (dto.siteId) {
      const site = await this.siteRepo.findById(tenantId, dto.siteId);
      if (!site) {
        return Result.fail(`Protected site '${dto.siteId}' not found for tenant`);
      }
    }

    const window = dto.window ?? AnalyticsWindow.HOURS_24;
    const fromDate = calculateWindowFrom(window);
    const limit = Math.min(50, Math.max(1, dto.limit ?? 10));

    const events = await this.eventRepo.findRawForAnalytics(tenantId, {
      siteId: dto.siteId,
      from: fromDate,
    });

    const threats = computeTopThreats(events, limit);

    return Result.ok({
      window,
      siteId: dto.siteId ?? null,
      from: fromDate.toISOString(),
      to: new Date().toISOString(),
      ...threats,
    });
  }
}
