import { Injectable } from '@nestjs/common';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import { SecurityEvent } from '../domain/security-event.entity';
import {
  WafAction,
  SecuritySeverity,
  SecurityEventQueryParams,
} from '../domain/security-event.types';
import { ISecurityEventRepository } from '../domain/security-event.repository.interface';

@Injectable()
export class PrismaSecurityEventRepository implements ISecurityEventRepository {
  constructor(private readonly prisma: PrismaService) {}

  async save(event: SecurityEvent): Promise<void> {
    await this.prisma.securityEvent.create({
      data: {
        id: event.id,
        tenantId: event.tenantId,
        siteId: event.siteId,
        requestId: event.requestId,
        clientIpHash: event.clientIpHash,
        method: event.method,
        path: event.path,
        action: event.action as any,
        wouldAction: event.wouldAction as any,
        reason: event.reason,
        riskScore: event.riskScore,
        severity: event.severity as any,
        stageUsed: event.stageUsed,
        ruleMatchesJson: event.ruleMatches as any,
        anomalyFlagsJson: event.anomalyFlags as any,
        degradedMode: event.degradedMode,
        modelVersion: event.modelVersion,
        policyVersion: event.policyVersion,
        latencyMs: event.latencyMs,
        redactedRequestJson: event.redactedRequest as any,
        createdAt: event.createdAt,
      },
    });
  }

  async saveBatch(events: SecurityEvent[]): Promise<void> {
    if (events.length === 0) return;

    await this.prisma.securityEvent.createMany({
      data: events.map((event) => ({
        id: event.id,
        tenantId: event.tenantId,
        siteId: event.siteId,
        requestId: event.requestId,
        clientIpHash: event.clientIpHash,
        method: event.method,
        path: event.path,
        action: event.action as any,
        wouldAction: event.wouldAction as any,
        reason: event.reason,
        riskScore: event.riskScore,
        severity: event.severity as any,
        stageUsed: event.stageUsed,
        ruleMatchesJson: event.ruleMatches as any,
        anomalyFlagsJson: event.anomalyFlags as any,
        degradedMode: event.degradedMode,
        modelVersion: event.modelVersion,
        policyVersion: event.policyVersion,
        latencyMs: event.latencyMs,
        redactedRequestJson: event.redactedRequest as any,
        createdAt: event.createdAt,
      })),
    });
  }

  async findById(tenantId: string, eventId: string): Promise<SecurityEvent | null> {
    const record = await this.prisma.securityEvent.findFirst({
      where: { id: eventId, tenantId },
    });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findByIds(tenantId: string, eventIds: string[]): Promise<SecurityEvent[]> {
    if (eventIds.length === 0) return [];
    const records = await this.prisma.securityEvent.findMany({
      where: {
        id: { in: eventIds },
        tenantId,
      },
    });
    return records.map((r) => this.toDomain(r));
  }

  async query(
    tenantId: string,
    params: SecurityEventQueryParams,
  ): Promise<{ items: SecurityEvent[]; total: number }> {
    const where: any = { tenantId };

    if (params.siteId) {
      where.siteId = params.siteId;
    }
    if (params.action) {
      where.action = params.action;
    }
    if (params.minRiskScore !== undefined || params.maxRiskScore !== undefined) {
      where.riskScore = {};
      if (params.minRiskScore !== undefined) where.riskScore.gte = params.minRiskScore;
      if (params.maxRiskScore !== undefined) where.riskScore.lte = params.maxRiskScore;
    }
    if (params.stageUsed) {
      where.stageUsed = params.stageUsed;
    }
    if (params.degradedMode !== undefined) {
      where.degradedMode = params.degradedMode;
    }
    if (params.pathContains) {
      where.path = { contains: params.pathContains, mode: 'insensitive' };
    }
    if (params.from || params.to) {
      where.createdAt = {};
      if (params.from) where.createdAt.gte = params.from;
      if (params.to) where.createdAt.lte = params.to;
    }

    const page = Math.max(1, params.page ?? 1);
    const limit = Math.min(100, Math.max(1, params.limit ?? 20));
    const skip = (page - 1) * limit;

    const [records, total] = await Promise.all([
      this.prisma.securityEvent.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.securityEvent.count({ where }),
    ]);

    return {
      items: records.map((r) => this.toDomain(r)),
      total,
    };
  }

  async findRawForAnalytics(
    tenantId: string,
    options: {
      siteId?: string;
      from?: Date;
      to?: Date;
      limit?: number;
    },
  ): Promise<SecurityEvent[]> {
    const where: any = { tenantId };
    if (options.siteId) where.siteId = options.siteId;
    if (options.from || options.to) {
      where.createdAt = {};
      if (options.from) where.createdAt.gte = options.from;
      if (options.to) where.createdAt.lte = options.to;
    }

    const records = await this.prisma.securityEvent.findMany({
      where,
      orderBy: { createdAt: 'asc' },
      take: options.limit ?? 5000,
    });

    return records.map((r) => this.toDomain(r));
  }

  private toDomain(record: any): SecurityEvent {
    return SecurityEvent.reconstitute(record.id, {
      tenantId: record.tenantId,
      siteId: record.siteId,
      requestId: record.requestId,
      clientIpHash: record.clientIpHash,
      method: record.method,
      path: record.path,
      action: record.action as WafAction,
      wouldAction: record.wouldAction as WafAction,
      reason: record.reason,
      riskScore: record.riskScore,
      severity: record.severity as SecuritySeverity,
      stageUsed: record.stageUsed,
      ruleMatches: Array.isArray(record.ruleMatchesJson) ? record.ruleMatchesJson : [],
      anomalyFlags: Array.isArray(record.anomalyFlagsJson) ? record.anomalyFlagsJson : [],
      degradedMode: record.degradedMode,
      modelVersion: record.modelVersion,
      policyVersion: record.policyVersion,
      latencyMs: record.latencyMs,
      redactedRequest: record.redactedRequestJson,
      createdAt: record.createdAt,
    });
  }
}
