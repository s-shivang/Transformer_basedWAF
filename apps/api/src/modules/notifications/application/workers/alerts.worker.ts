import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as crypto from 'crypto';
import { IJobQueue, Job } from '@shared/infrastructure/queues/job-queue.interface';
import { JOB_QUEUE_TOKEN, QUEUES, JOBS } from '@shared/infrastructure/queues/queue.constants';
import {
  evaluateAlertTriggers,
  IngestedEventCandidate,
} from '../../domain/alert-evaluator';
import { Notification } from '../../domain/notification.entity';
import {
  INotificationRepository,
  NOTIFICATION_REPOSITORY,
} from '../../domain/repositories/notification.repository.interface';
import {
  IWebhookEndpointRepository,
  WEBHOOK_ENDPOINT_REPOSITORY,
} from '../../domain/repositories/webhook-endpoint.repository.interface';
import {
  IWebhookHttpSender,
  WEBHOOK_HTTP_SENDER,
} from '../ports/webhook-http-sender.port';
import { signWebhookPayload } from '../../domain/webhook-signature';

export interface AlertJobPayload {
  tenantId: string;
  events: IngestedEventCandidate[];
}

@Injectable()
export class AlertsWorker implements OnModuleInit {
  private readonly logger = new Logger(AlertsWorker.name);

  constructor(
    @Inject(JOB_QUEUE_TOKEN) private readonly jobQueue: IJobQueue,
    @Inject(NOTIFICATION_REPOSITORY)
    private readonly notificationRepo: INotificationRepository,
    @Inject(WEBHOOK_ENDPOINT_REPOSITORY)
    private readonly webhookRepo: IWebhookEndpointRepository,
    @Inject(WEBHOOK_HTTP_SENDER)
    private readonly httpSender: IWebhookHttpSender,
  ) {}

  onModuleInit() {
    this.jobQueue.registerProcessor<AlertJobPayload>(
      QUEUES.ALERTS,
      this.processJob.bind(this),
    );
  }

  async processJob(job: Job<AlertJobPayload>): Promise<void> {
    const { tenantId, events } = job.data;
    if (!tenantId || !events || events.length === 0) return;

    const triggers = evaluateAlertTriggers(events);
    if (triggers.length === 0) return;

    const activeEndpoints = await this.webhookRepo.findActiveByTenant(tenantId);

    for (const trigger of triggers) {
      // 1. Create and persist Notification
      const notificationId = crypto.randomUUID();
      const notification = Notification.create(notificationId, {
        tenantId,
        siteId: trigger.siteId,
        severity: trigger.severity,
        type: trigger.type,
        title: trigger.title,
        message: trigger.message,
        metadataJson: trigger.metadata,
      });

      await this.notificationRepo.save(notification);

      // 2. Dispatch to matching webhooks
      const subscribedEndpoints = activeEndpoints.filter((ep) =>
        ep.isSubscribedTo(trigger.type),
      );

      for (const endpoint of subscribedEndpoints) {
        const webhookPayload = {
          eventId: crypto.randomUUID(),
          eventType: trigger.type,
          severity: trigger.severity,
          tenantId,
          siteId: trigger.siteId || null,
          title: trigger.title,
          message: trigger.message,
          data: trigger.metadata,
          timestamp: new Date().toISOString(),
        };

        const payloadStr = JSON.stringify(webhookPayload);
        const signature = signWebhookPayload(payloadStr, endpoint.secretHash);

        try {
          const res = await this.httpSender.send(
            endpoint.url.value,
            webhookPayload,
            signature,
          );
          if (!res.success) {
            this.logger.warn(
              `Webhook dispatch failed to ${endpoint.url.value}: ${res.error || res.statusCode}`,
            );
          }
        } catch (err: any) {
          this.logger.error(
            `Error dispatching webhook to ${endpoint.url.value}: ${err.message}`,
          );
        }
      }
    }
  }
}
