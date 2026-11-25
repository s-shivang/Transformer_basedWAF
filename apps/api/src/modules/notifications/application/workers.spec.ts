import { InMemoryJobQueue } from '@shared/infrastructure/queues/in-memory-job-queue';
import { InMemoryNotificationRepository } from '../infrastructure/repositories/notification.repository';
import { InMemoryWebhookEndpointRepository } from '../infrastructure/repositories/webhook-endpoint.repository';
import { InMemoryWebhookHttpSender } from '../infrastructure/adapters/webhook-http-sender.adapter';
import { InMemoryWafGatewayClient } from '../infrastructure/adapters/waf-gateway-client.adapter';
import { InMemoryFeedbackExportDataProvider } from '../infrastructure/adapters/feedback-export-data-provider.adapter';
import { AlertsWorker } from './workers/alerts.worker';
import { PolicySyncWorker } from './workers/policy-sync.worker';
import { FeedbackExportWorker } from './workers/feedback-export.worker';
import { WebhookEndpoint } from '../domain/webhook-endpoint.entity';
import { verifyWebhookSignature } from '../domain/webhook-signature';

describe('Phase 13 Async Workers Unit Tests', () => {
  let jobQueue: InMemoryJobQueue;
  let notificationRepo: InMemoryNotificationRepository;
  let webhookRepo: InMemoryWebhookEndpointRepository;
  let httpSender: InMemoryWebhookHttpSender;
  let gatewayClient: InMemoryWafGatewayClient;
  let dataProvider: InMemoryFeedbackExportDataProvider;

  beforeEach(() => {
    jobQueue = new InMemoryJobQueue();
    notificationRepo = new InMemoryNotificationRepository();
    webhookRepo = new InMemoryWebhookEndpointRepository();
    httpSender = new InMemoryWebhookHttpSender();
    gatewayClient = new InMemoryWafGatewayClient();
    dataProvider = new InMemoryFeedbackExportDataProvider();
  });

  describe('AlertsWorker', () => {
    it('creates notification and dispatches signed webhook on attack surge', async () => {
      const worker = new AlertsWorker(
        jobQueue,
        notificationRepo,
        webhookRepo,
        httpSender,
      );
      worker.onModuleInit();

      // Register active webhook
      const webhook = WebhookEndpoint.create('wh-1', {
        tenantId: 'tenant-a',
        name: 'SecOps Webhook',
        url: 'https://security.example.com/alerts',
        secretHash: 'whsec_secret_key_123',
        events: ['ATTACK_SPIKE'],
      });
      await webhookRepo.save(webhook);

      // Enqueue 5 BLOCK events
      await jobQueue.enqueue('alerts', 'process-alerts', {
        tenantId: 'tenant-a',
        events: [
          { siteId: 'site-1', action: 'BLOCK' },
          { siteId: 'site-1', action: 'BLOCK' },
          { siteId: 'site-1', action: 'BLOCK' },
          { siteId: 'site-1', action: 'BLOCK' },
          { siteId: 'site-1', action: 'BLOCK' },
        ],
      });

      await jobQueue.drain();

      // Assert notification created
      const { notifications } = await notificationRepo.findMany('tenant-a');
      expect(notifications).toHaveLength(1);
      expect(notifications[0].type).toBe('ATTACK_SPIKE');
      expect(notifications[0].severity).toBe('CRITICAL');

      // Assert webhook dispatched with valid HMAC signature
      expect(httpSender.dispatched).toHaveLength(1);
      const delivery = httpSender.dispatched[0];
      expect(delivery.url).toBe('https://security.example.com/alerts');
      expect(delivery.payload.eventType).toBe('ATTACK_SPIKE');

      const isValid = verifyWebhookSignature(
        JSON.stringify(delivery.payload),
        'whsec_secret_key_123',
        delivery.signature,
      );
      expect(isValid).toBe(true);
    });
  });

  describe('PolicySyncWorker', () => {
    it('successfully syncs policy when gateway is reachable', async () => {
      const worker = new PolicySyncWorker(jobQueue, notificationRepo, gatewayClient);
      worker.onModuleInit();

      await jobQueue.enqueue('policy-sync', 'sync-policy', {
        tenantId: 'tenant-a',
        siteId: 'site-1',
        version: 2,
        effectivePolicy: { mode: 'BLOCKING' },
      });

      await jobQueue.drain();

      expect(gatewayClient.syncedPolicies).toHaveLength(1);
      expect(gatewayClient.syncedPolicies[0].siteId).toBe('site-1');

      const { notifications } = await notificationRepo.findMany('tenant-a');
      expect(notifications).toHaveLength(0);
    });

    it('creates POLICY_SYNC_FAILED warning notification when gateway fails', async () => {
      gatewayClient.shouldFail = true;
      const worker = new PolicySyncWorker(jobQueue, notificationRepo, gatewayClient);
      worker.onModuleInit();

      await jobQueue.enqueue('policy-sync', 'sync-policy', {
        tenantId: 'tenant-a',
        siteId: 'site-1',
        version: 2,
        effectivePolicy: { mode: 'BLOCKING' },
      });

      await jobQueue.drain();

      const { notifications } = await notificationRepo.findMany('tenant-a');
      expect(notifications).toHaveLength(1);
      expect(notifications[0].type).toBe('POLICY_SYNC_FAILED');
      expect(notifications[0].severity).toBe('WARNING');
      expect(notifications[0].metadataJson?.version).toBe(2);
    });
  });

  describe('FeedbackExportWorker', () => {
    it('exports ONLY approved feedback and logs audit trail', async () => {
      const worker = new FeedbackExportWorker(jobQueue, notificationRepo, dataProvider);
      worker.onModuleInit();

      dataProvider.approvedFeedback = [
        {
          id: 'fb-1',
          tenantId: 'tenant-a',
          securityEventId: 'evt-1',
          label: 'FALSE_POSITIVE',
          reviewStatus: 'APPROVED',
          notes: 'Legit webhook',
          createdAt: new Date(),
          event: {
            method: 'POST',
            path: '/api/v1/webhook',
            riskScore: 0.92,
            action: 'BLOCK',
          },
        },
      ];

      await jobQueue.enqueue('feedback-export', 'export-feedback', {
        tenantId: 'tenant-a',
        userId: 'user-admin',
      });

      await jobQueue.drain();

      // Assert audit log recorded
      expect(dataProvider.auditRecords).toHaveLength(1);
      expect(dataProvider.auditRecords[0].metadata.recordCount).toBe(1);
      expect(dataProvider.auditRecords[0].metadata.sha256Digest).toBeDefined();

      // Assert notification created
      const { notifications } = await notificationRepo.findMany('tenant-a');
      expect(notifications).toHaveLength(1);
      expect(notifications[0].type).toBe('FEEDBACK_EXPORT_READY');
      expect(notifications[0].severity).toBe('INFO');
      expect(notifications[0].metadataJson?.recordCount).toBe(1);
    });
  });
});
