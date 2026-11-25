import { Module } from '@nestjs/common';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import { NOTIFICATION_REPOSITORY } from './domain/repositories/notification.repository.interface';
import { WEBHOOK_ENDPOINT_REPOSITORY } from './domain/repositories/webhook-endpoint.repository.interface';
import { PrismaNotificationRepository } from './infrastructure/repositories/notification.repository';
import { PrismaWebhookEndpointRepository } from './infrastructure/repositories/webhook-endpoint.repository';
import { WEBHOOK_HTTP_SENDER } from './application/ports/webhook-http-sender.port';
import { FetchWebhookHttpSender } from './infrastructure/adapters/webhook-http-sender.adapter';
import { WAF_GATEWAY_CLIENT } from './application/ports/waf-gateway-client.port';
import { HttpWafGatewayClient } from './infrastructure/adapters/waf-gateway-client.adapter';
import { FEEDBACK_EXPORT_DATA_PROVIDER } from './application/ports/feedback-export-data-provider.port';
import { PrismaFeedbackExportDataProvider } from './infrastructure/adapters/feedback-export-data-provider.adapter';

import { AlertsWorker } from './application/workers/alerts.worker';
import { PolicySyncWorker } from './application/workers/policy-sync.worker';
import { FeedbackExportWorker } from './application/workers/feedback-export.worker';

import { GetNotificationsUseCase } from './application/use-cases/get-notifications.use-case';
import { MarkNotificationReadUseCase } from './application/use-cases/mark-notification-read.use-case';
import { CreateWebhookUseCase } from './application/use-cases/create-webhook.use-case';
import {
  ListWebhooksUseCase,
  DeleteWebhookUseCase,
} from './application/use-cases/webhook-queries.use-case';
import { EnqueueFeedbackExportUseCase } from './application/use-cases/enqueue-feedback-export.use-case';

import { NotificationsController } from './presentation/notifications.controller';
import { WebhooksController } from './presentation/webhooks.controller';

@Module({
  controllers: [NotificationsController, WebhooksController],
  providers: [
    PrismaService,
    // Repositories
    {
      provide: NOTIFICATION_REPOSITORY,
      useClass: PrismaNotificationRepository,
    },
    {
      provide: WEBHOOK_ENDPOINT_REPOSITORY,
      useClass: PrismaWebhookEndpointRepository,
    },
    // Adapters
    {
      provide: WEBHOOK_HTTP_SENDER,
      useClass: FetchWebhookHttpSender,
    },
    {
      provide: WAF_GATEWAY_CLIENT,
      useClass: HttpWafGatewayClient,
    },
    {
      provide: FEEDBACK_EXPORT_DATA_PROVIDER,
      useClass: PrismaFeedbackExportDataProvider,
    },
    // Workers
    AlertsWorker,
    PolicySyncWorker,
    FeedbackExportWorker,
    // Use Cases
    GetNotificationsUseCase,
    MarkNotificationReadUseCase,
    CreateWebhookUseCase,
    ListWebhooksUseCase,
    DeleteWebhookUseCase,
    EnqueueFeedbackExportUseCase,
  ],
  exports: [
    NOTIFICATION_REPOSITORY,
    WEBHOOK_ENDPOINT_REPOSITORY,
    WEBHOOK_HTTP_SENDER,
    WAF_GATEWAY_CLIENT,
    FEEDBACK_EXPORT_DATA_PROVIDER,
    AlertsWorker,
    PolicySyncWorker,
    FeedbackExportWorker,
  ],
})
export class NotificationsModule {}
