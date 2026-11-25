import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import {
  ApprovedFeedbackRow,
  IFeedbackExportDataProvider,
} from '../../application/ports/feedback-export-data-provider.port';

@Injectable()
export class PrismaFeedbackExportDataProvider
  implements IFeedbackExportDataProvider
{
  constructor(private readonly prisma: PrismaService) {}

  async getApprovedFeedback(tenantId: string): Promise<ApprovedFeedbackRow[]> {
    const rawList = await this.prisma.eventFeedback.findMany({
      where: {
        tenantId,
        reviewStatus: 'APPROVED' as any,
      },
      include: {
        securityEvent: true,
      },
      orderBy: { createdAt: 'asc' },
    });

    return rawList.map((item) => ({
      id: item.id,
      tenantId: item.tenantId,
      siteId: item.siteId,
      securityEventId: item.securityEventId,
      label: item.label,
      reviewStatus: item.reviewStatus,
      notes: item.notes,
      reviewNotes: item.reviewNotes,
      createdAt: item.createdAt,
      reviewedAt: item.reviewedAt,
      event: item.securityEvent
        ? {
            requestId: item.securityEvent.requestId,
            method: item.securityEvent.method,
            path: item.securityEvent.path,
            riskScore: item.securityEvent.riskScore,
            action: item.securityEvent.action,
            stageUsed: item.securityEvent.stageUsed,
          }
        : null,
    }));
  }

  async recordExportAudit(
    tenantId: string,
    userId: string,
    metadata: {
      recordCount: number;
      sha256Digest: string;
      exportedAt: string;
    },
  ): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        id: crypto.randomUUID(),
        tenantId,
        userId,
        action: 'FEEDBACK_DATASET_EXPORTED',
        resource: 'FEEDBACK',
        metadata: metadata as any,
      },
    });
  }
}

export class InMemoryFeedbackExportDataProvider
  implements IFeedbackExportDataProvider
{
  public approvedFeedback: ApprovedFeedbackRow[] = [];
  public auditRecords: { tenantId: string; userId: string; metadata: any }[] =
    [];

  async getApprovedFeedback(tenantId: string): Promise<ApprovedFeedbackRow[]> {
    return this.approvedFeedback.filter((f) => f.tenantId === tenantId);
  }

  async recordExportAudit(
    tenantId: string,
    userId: string,
    metadata: any,
  ): Promise<void> {
    this.auditRecords.push({ tenantId, userId, metadata });
  }

  clear() {
    this.approvedFeedback = [];
    this.auditRecords = [];
  }
}
