import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as crypto from 'crypto';
import { IJobQueue, Job } from '@shared/infrastructure/queues/job-queue.interface';
import { JOB_QUEUE_TOKEN, QUEUES, JOBS } from '@shared/infrastructure/queues/queue.constants';
import {
  INotificationRepository,
  NOTIFICATION_REPOSITORY,
} from '../../domain/repositories/notification.repository.interface';
import {
  IWafGatewayClient,
  WAF_GATEWAY_CLIENT,
} from '../ports/waf-gateway-client.port';
import { Notification } from '../../domain/notification.entity';

export interface PolicySyncJobPayload {
  tenantId: string;
  siteId: string;
  version: number;
  effectivePolicy?: any;
}

@Injectable()
export class PolicySyncWorker implements OnModuleInit {
  private readonly logger = new Logger(PolicySyncWorker.name);

  constructor(
    @Inject(JOB_QUEUE_TOKEN) private readonly jobQueue: IJobQueue,
    @Inject(NOTIFICATION_REPOSITORY)
    private readonly notificationRepo: INotificationRepository,
    @Inject(WAF_GATEWAY_CLIENT)
    private readonly gatewayClient: IWafGatewayClient,
  ) {}

  onModuleInit() {
    this.jobQueue.registerProcessor<PolicySyncJobPayload>(
      QUEUES.POLICY_SYNC,
      this.processJob.bind(this),
    );
  }

  async processJob(job: Job<PolicySyncJobPayload>): Promise<void> {
    const { tenantId, siteId, version, effectivePolicy } = job.data;
    if (!tenantId || !siteId) return;

    try {
      const result = await this.gatewayClient.syncPolicy(siteId, effectivePolicy);
      if (!result.success) {
        throw new Error(result.error || `HTTP ${result.statusCode}`);
      }
      this.logger.log(
        `Successfully synced policy v${version} for site ${siteId} to WAF Gateway.`,
      );
    } catch (err: any) {
      this.logger.warn(
        `Policy sync attempt failed for site ${siteId} (attempt ${(job.attemptsMade || 0) + 1}): ${err.message}`,
      );

      // On final failure, create WARNING Notification for tenant
      const notificationId = crypto.randomUUID();
      const notification = Notification.create(notificationId, {
        tenantId,
        siteId,
        severity: 'WARNING',
        type: 'POLICY_SYNC_FAILED',
        title: 'WAF Policy Gateway Sync Failed',
        message: `Failed to push active WAF policy v${version} to Data Plane gateway: ${err.message}`,
        metadataJson: {
          siteId,
          version,
          error: err.message,
          attempts: (job.attemptsMade || 0) + 1,
        },
      });

      await this.notificationRepo.save(notification);
      throw err; // Trigger retry backoff
    }
  }
}
