import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as crypto from 'crypto';
import { IJobQueue, Job } from '@shared/infrastructure/queues/job-queue.interface';
import { JOB_QUEUE_TOKEN, QUEUES, JOBS } from '@shared/infrastructure/queues/queue.constants';
import {
  INotificationRepository,
  NOTIFICATION_REPOSITORY,
} from '../../domain/repositories/notification.repository.interface';
import {
  IFeedbackExportDataProvider,
  FEEDBACK_EXPORT_DATA_PROVIDER,
} from '../ports/feedback-export-data-provider.port';
import { Notification } from '../../domain/notification.entity';

export interface FeedbackExportJobPayload {
  tenantId: string;
  userId: string;
}

@Injectable()
export class FeedbackExportWorker implements OnModuleInit {
  private readonly logger = new Logger(FeedbackExportWorker.name);

  constructor(
    @Inject(JOB_QUEUE_TOKEN) private readonly jobQueue: IJobQueue,
    @Inject(NOTIFICATION_REPOSITORY)
    private readonly notificationRepo: INotificationRepository,
    @Inject(FEEDBACK_EXPORT_DATA_PROVIDER)
    private readonly dataProvider: IFeedbackExportDataProvider,
  ) {}

  onModuleInit() {
    this.jobQueue.registerProcessor<FeedbackExportJobPayload>(
      QUEUES.FEEDBACK_EXPORT,
      this.processJob.bind(this),
    );
  }

  async processJob(job: Job<FeedbackExportJobPayload>): Promise<void> {
    const { tenantId, userId } = job.data;
    if (!tenantId) return;

    // 1. Fetch ONLY approved feedback rows for this tenant
    const approvedRows = await this.dataProvider.getApprovedFeedback(tenantId);

    // 2. Format redacted JSONL records (CRITICAL ML SAFETY: zero auto-retrain, isolated dataset curation)
    const jsonlLines = approvedRows.map((row) =>
      JSON.stringify({
        id: row.id,
        tenantId: row.tenantId,
        securityEventId: row.securityEventId,
        label: row.label,
        reviewStatus: row.reviewStatus,
        notes: row.notes,
        reviewedAt: row.reviewedAt ? new Date(row.reviewedAt).toISOString() : null,
        method: row.event?.method,
        path: row.event?.path,
        riskScore: row.event?.riskScore,
        action: row.event?.action,
        stageUsed: row.event?.stageUsed,
      }),
    );

    const payloadString = jsonlLines.join('\n');
    const sha256Digest = crypto
      .createHash('sha256')
      .update(payloadString, 'utf8')
      .digest('hex');

    const exportedAt = new Date().toISOString();

    // 3. Record AuditLog
    await this.dataProvider.recordExportAudit(tenantId, userId, {
      recordCount: approvedRows.length,
      sha256Digest,
      exportedAt,
    });

    // 4. Create Notification for tenant
    const notificationId = crypto.randomUUID();
    const notification = Notification.create(notificationId, {
      tenantId,
      severity: 'INFO',
      type: 'FEEDBACK_EXPORT_READY',
      title: 'False-Positive Feedback Dataset Export Ready',
      message: `Exported ${approvedRows.length} approved feedback records for offline ML dataset curation.`,
      metadataJson: {
        recordCount: approvedRows.length,
        sha256Digest,
        exportedAt,
      },
    });

    await this.notificationRepo.save(notification);

    this.logger.log(
      `Feedback export complete for tenant ${tenantId}: ${approvedRows.length} records, SHA256: ${sha256Digest.substring(0, 12)}...`,
    );
  }
}
