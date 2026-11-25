import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as cookieParser from 'cookie-parser';
import * as crypto from 'crypto';
import { AppModule } from '../src/app.module';

import { TENANT_REPOSITORY } from '../src/modules/tenants/domain/tenant.repository.interface';
import { InMemoryTenantRepository } from '../src/modules/tenants/infrastructure/in-memory-tenant.repository';
import {
  USER_REPOSITORY,
  MEMBERSHIP_REPOSITORY,
  REFRESH_SESSION_REPOSITORY,
  AUDIT_LOG_REPOSITORY,
} from '../src/modules/identity/domain/identity.repository.interfaces';
import {
  InMemoryUserRepository,
  InMemoryMembershipRepository,
  InMemoryRefreshSessionRepository,
  InMemoryAuditLogRepository,
} from '../src/modules/identity/infrastructure/in-memory-identity.repositories';
import { PROTECTED_SITE_REPOSITORY } from '../src/modules/protected-sites/domain/protected-site.repository.interface';
import { InMemoryProtectedSiteRepository } from '../src/modules/protected-sites/infrastructure/in-memory-protected-site.repository';
import { WAF_POLICY_REPOSITORY } from '../src/modules/waf-policies/domain/waf-policy.repository.interface';
import { InMemoryWafPolicyRepository } from '../src/modules/waf-policies/infrastructure/in-memory-waf-policy.repository';
import { SECURITY_EVENT_REPOSITORY } from '../src/modules/security-events/domain/security-event.repository.interface';
import { InMemorySecurityEventRepository } from '../src/modules/security-events/infrastructure/in-memory-security-event.repository';
import { EVENT_FEEDBACK_REPOSITORY } from '../src/modules/security-events/domain/event-feedback.repository.interface';
import { InMemoryEventFeedbackRepository } from '../src/modules/security-events/infrastructure/in-memory-event-feedback.repository';
import { NOTIFICATION_REPOSITORY } from '../src/modules/notifications/domain/repositories/notification.repository.interface';
import { InMemoryNotificationRepository } from '../src/modules/notifications/infrastructure/repositories/notification.repository';
import { WEBHOOK_ENDPOINT_REPOSITORY } from '../src/modules/notifications/domain/repositories/webhook-endpoint.repository.interface';
import { InMemoryWebhookEndpointRepository } from '../src/modules/notifications/infrastructure/repositories/webhook-endpoint.repository';
import { WEBHOOK_HTTP_SENDER } from '../src/modules/notifications/application/ports/webhook-http-sender.port';
import { InMemoryWebhookHttpSender } from '../src/modules/notifications/infrastructure/adapters/webhook-http-sender.adapter';
import { WAF_GATEWAY_CLIENT } from '../src/modules/notifications/application/ports/waf-gateway-client.port';
import { InMemoryWafGatewayClient } from '../src/modules/notifications/infrastructure/adapters/waf-gateway-client.adapter';
import { FEEDBACK_EXPORT_DATA_PROVIDER } from '../src/modules/notifications/application/ports/feedback-export-data-provider.port';
import { InMemoryFeedbackExportDataProvider } from '../src/modules/notifications/infrastructure/adapters/feedback-export-data-provider.adapter';
import { JOB_QUEUE_TOKEN } from '../src/shared/infrastructure/queues/queue.constants';
import { InMemoryJobQueue } from '../src/shared/infrastructure/queues/in-memory-job-queue';

import { TOKEN_SERVICE, ITokenService } from '../src/modules/identity/infrastructure/token.service';
import { Tenant } from '../src/modules/tenants/domain/tenant.entity';
import { TenantId } from '../src/modules/tenants/domain/tenant-id.vo';
import { TenantSlug } from '../src/modules/tenants/domain/tenant-slug.vo';
import { User } from '../src/modules/identity/domain/user.entity';
import { Email } from '../src/modules/identity/domain/email.vo';
import { Membership } from '../src/modules/identity/domain/membership.entity';
import { UserRole } from '../src/modules/identity/domain/user-role';
import { ProtectedSite } from '../src/modules/protected-sites/domain/protected-site.entity';
import { SiteDomain } from '../src/modules/protected-sites/domain/site-domain.vo';
import { OriginUrl } from '../src/modules/protected-sites/domain/origin-url.vo';
import { WafPolicy, WafMode } from '../src/modules/waf-policies/domain/waf-policy.entity';
import { verifyWebhookSignature } from '../src/modules/notifications/domain/webhook-signature';

describe('Phase 13 Background Jobs, Alerting & Async Bridge (E2E)', () => {
  let app: INestApplication;
  let tenantRepo: InMemoryTenantRepository;
  let userRepo: InMemoryUserRepository;
  let memberRepo: InMemoryMembershipRepository;
  let sessionRepo: InMemoryRefreshSessionRepository;
  let auditRepo: InMemoryAuditLogRepository;
  let siteRepo: InMemoryProtectedSiteRepository;
  let policyRepo: InMemoryWafPolicyRepository;
  let eventRepo: InMemorySecurityEventRepository;
  let feedbackRepo: InMemoryEventFeedbackRepository;
  let notificationRepo: InMemoryNotificationRepository;
  let webhookRepo: InMemoryWebhookEndpointRepository;
  let httpSender: InMemoryWebhookHttpSender;
  let gatewayClient: InMemoryWafGatewayClient;
  let dataProvider: InMemoryFeedbackExportDataProvider;
  let jobQueue: InMemoryJobQueue;
  let tokenService: ITokenService;

  let ownerTokenA: string;
  let adminTokenA: string;
  let analystTokenA: string;
  let viewerTokenA: string;
  let ownerTokenB: string;

  let tenantIdA: string;
  let tenantIdB: string;
  let siteIdA: string;
  let siteIdB: string;

  const validIngestKey = 'waf-internal-ingest-secret-dev';

  beforeAll(async () => {
    tenantRepo = new InMemoryTenantRepository();
    userRepo = new InMemoryUserRepository();
    memberRepo = new InMemoryMembershipRepository();
    sessionRepo = new InMemoryRefreshSessionRepository();
    auditRepo = new InMemoryAuditLogRepository();
    siteRepo = new InMemoryProtectedSiteRepository();
    policyRepo = new InMemoryWafPolicyRepository();
    eventRepo = new InMemorySecurityEventRepository();
    feedbackRepo = new InMemoryEventFeedbackRepository();
    notificationRepo = new InMemoryNotificationRepository();
    webhookRepo = new InMemoryWebhookEndpointRepository();
    httpSender = new InMemoryWebhookHttpSender();
    gatewayClient = new InMemoryWafGatewayClient();
    dataProvider = new InMemoryFeedbackExportDataProvider();
    jobQueue = new InMemoryJobQueue();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(TENANT_REPOSITORY)
      .useValue(tenantRepo)
      .overrideProvider(USER_REPOSITORY)
      .useValue(userRepo)
      .overrideProvider(MEMBERSHIP_REPOSITORY)
      .useValue(memberRepo)
      .overrideProvider(REFRESH_SESSION_REPOSITORY)
      .useValue(sessionRepo)
      .overrideProvider(AUDIT_LOG_REPOSITORY)
      .useValue(auditRepo)
      .overrideProvider(PROTECTED_SITE_REPOSITORY)
      .useValue(siteRepo)
      .overrideProvider(WAF_POLICY_REPOSITORY)
      .useValue(policyRepo)
      .overrideProvider(SECURITY_EVENT_REPOSITORY)
      .useValue(eventRepo)
      .overrideProvider(EVENT_FEEDBACK_REPOSITORY)
      .useValue(feedbackRepo)
      .overrideProvider(NOTIFICATION_REPOSITORY)
      .useValue(notificationRepo)
      .overrideProvider(WEBHOOK_ENDPOINT_REPOSITORY)
      .useValue(webhookRepo)
      .overrideProvider(WEBHOOK_HTTP_SENDER)
      .useValue(httpSender)
      .overrideProvider(WAF_GATEWAY_CLIENT)
      .useValue(gatewayClient)
      .overrideProvider(FEEDBACK_EXPORT_DATA_PROVIDER)
      .useValue(dataProvider)
      .overrideProvider(JOB_QUEUE_TOKEN)
      .useValue(jobQueue)
      .compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.use(cookieParser());
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );

    await app.init();

    tokenService = moduleFixture.get<ITokenService>(TOKEN_SERVICE);

    // Setup Tenant A and Tenant B
    tenantIdA = crypto.randomUUID();
    const tenantA = Tenant.create({ name: 'Acme Corp', slug: TenantSlug.create('acme-corp').getValue() }, TenantId.create(tenantIdA).getValue()).getValue();
    await tenantRepo.save(tenantA);

    tenantIdB = crypto.randomUUID();
    const tenantB = Tenant.create({ name: 'Beta Corp', slug: TenantSlug.create('beta-corp').getValue() }, TenantId.create(tenantIdB).getValue()).getValue();
    await tenantRepo.save(tenantB);

    // Users and Memberships
    const ownerAId = crypto.randomUUID();
    await userRepo.save(User.create({ email: Email.create('owner@acme.com').getValue(), passwordHash: 'hash', name: 'Owner A' }, ownerAId).getValue());
    await memberRepo.save(Membership.create({ tenantId: tenantIdA, userId: ownerAId, role: UserRole.OWNER }).getValue());

    const adminAId = crypto.randomUUID();
    await userRepo.save(User.create({ email: Email.create('admin@acme.com').getValue(), passwordHash: 'hash', name: 'Admin A' }, adminAId).getValue());
    await memberRepo.save(Membership.create({ tenantId: tenantIdA, userId: adminAId, role: UserRole.ADMIN }).getValue());

    const analystAId = crypto.randomUUID();
    await userRepo.save(User.create({ email: Email.create('analyst@acme.com').getValue(), passwordHash: 'hash', name: 'Analyst A' }, analystAId).getValue());
    await memberRepo.save(Membership.create({ tenantId: tenantIdA, userId: analystAId, role: UserRole.ANALYST }).getValue());

    const viewerAId = crypto.randomUUID();
    await userRepo.save(User.create({ email: Email.create('viewer@acme.com').getValue(), passwordHash: 'hash', name: 'Viewer A' }, viewerAId).getValue());
    await memberRepo.save(Membership.create({ tenantId: tenantIdA, userId: viewerAId, role: UserRole.VIEWER }).getValue());

    const ownerBId = crypto.randomUUID();
    await userRepo.save(User.create({ email: Email.create('owner@beta.com').getValue(), passwordHash: 'hash', name: 'Owner B' }, ownerBId).getValue());
    await memberRepo.save(Membership.create({ tenantId: tenantIdB, userId: ownerBId, role: UserRole.OWNER }).getValue());

    // Generate JWT access tokens
    ownerTokenA = tokenService.generateAccessToken({ sub: ownerAId, tenantId: tenantIdA, role: UserRole.OWNER, email: 'owner@acme.com' });
    adminTokenA = tokenService.generateAccessToken({ sub: adminAId, tenantId: tenantIdA, role: UserRole.ADMIN, email: 'admin@acme.com' });
    analystTokenA = tokenService.generateAccessToken({ sub: analystAId, tenantId: tenantIdA, role: UserRole.ANALYST, email: 'analyst@acme.com' });
    viewerTokenA = tokenService.generateAccessToken({ sub: viewerAId, tenantId: tenantIdA, role: UserRole.VIEWER, email: 'viewer@acme.com' });
    ownerTokenB = tokenService.generateAccessToken({ sub: ownerBId, tenantId: tenantIdB, role: UserRole.OWNER, email: 'owner@beta.com' });

    // Create Site A and Policy A
    siteIdA = crypto.randomUUID();
    const siteA = ProtectedSite.create({
      tenantId: tenantIdA,
      name: 'Acme API',
      domain: SiteDomain.create('api.acme.com').getValue(),
      originUrl: OriginUrl.create('http://backend:8080').getValue(),
    }, siteIdA).getValue();
    await siteRepo.save(siteA);

    const policyA = WafPolicy.createDefault(tenantIdA, siteIdA);
    await policyRepo.save(policyA);

    // Create Site B and Policy B
    siteIdB = crypto.randomUUID();
    const siteB = ProtectedSite.create({
      tenantId: tenantIdB,
      name: 'Beta Portal',
      domain: SiteDomain.create('beta.com').getValue(),
      originUrl: OriginUrl.create('http://beta:8080').getValue(),
    }, siteIdB).getValue();
    await siteRepo.save(siteB);

    const policyB = WafPolicy.createDefault(tenantIdB, siteIdB);
    await policyRepo.save(policyB);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Webhook Endpoints Management (/api/v1/webhooks)', () => {
    let createdWebhookId: string;
    let createdSecret: string;

    it('rejects webhook creation by ANALYST or VIEWER (403 Forbidden)', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/webhooks')
        .set('Cookie', `waf_access_token=${analystTokenA}`)
        .send({
          name: 'Analyst Webhook',
          url: 'https://pagerduty.example.com/alerts',
        })
        .expect(403);

      await request(app.getHttpServer())
        .post('/api/v1/webhooks')
        .set('Cookie', `waf_access_token=${viewerTokenA}`)
        .send({
          name: 'Viewer Webhook',
          url: 'https://pagerduty.example.com/alerts',
        })
        .expect(403);
    });

    it('rejects SSRF cloud metadata targets (169.254.169.254)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/webhooks')
        .set('Cookie', `waf_access_token=${adminTokenA}`)
        .send({
          name: 'Malicious Webhook',
          url: 'https://169.254.169.254/latest/meta-data',
        })
        .expect(400);

      expect(res.body.message).toContain('SSRF Protection Violation');
    });

    it('allows ADMIN to create valid HTTPS webhook and returns raw secret once', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/webhooks')
        .set('Cookie', `waf_access_token=${adminTokenA}`)
        .send({
          name: 'Production Slack Alerts',
          url: 'https://hooks.slack.com/services/T00/B00/X00',
          events: ['ATTACK_SPIKE', 'ML_DEGRADED'],
        })
        .expect(201);

      expect(res.body.id).toBeDefined();
      expect(res.body.name).toBe('Production Slack Alerts');
      expect(res.body.url).toBe('https://hooks.slack.com/services/T00/B00/X00');
      expect(res.body.secret).toMatch(/^waf_whsec_/);
      createdWebhookId = res.body.id;
      createdSecret = res.body.secret;
    });

    it('lists webhooks for tenant WITHOUT exposing raw secret', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/webhooks')
        .set('Cookie', `waf_access_token=${viewerTokenA}`)
        .expect(200);

      expect(res.body).toHaveLength(1);
      expect(res.body[0].id).toBe(createdWebhookId);
      expect(res.body[0].secret).toBeUndefined();
      expect(res.body[0].secretHash).toBeUndefined();
    });

    it('prevents Tenant B from listing or deleting Tenant A webhook (Cross-Tenant Isolation)', async () => {
      // Tenant B lists webhooks -> sees 0
      const listRes = await request(app.getHttpServer())
        .get('/api/v1/webhooks')
        .set('Cookie', `waf_access_token=${ownerTokenB}`)
        .expect(200);

      expect(listRes.body).toHaveLength(0);

      // Tenant B tries to delete Tenant A webhook -> 404
      await request(app.getHttpServer())
        .delete(`/api/v1/webhooks/${createdWebhookId}`)
        .set('Cookie', `waf_access_token=${ownerTokenB}`)
        .expect(404);
    });
  });

  describe('Alerts Worker & Ingest Event Integration', () => {
    it('ingesting 5 BLOCK events triggers alert worker, creates Notification, and dispatches HMAC-signed webhook', async () => {
      httpSender.clear();

      const eventsPayload = [1, 2, 3, 4, 5].map((i) => ({
        tenantId: tenantIdA,
        siteId: siteIdA,
        requestId: `req-blk-${i}`,
        method: 'POST',
        path: '/admin/login',
        action: 'BLOCK',
        riskScore: 0.95,
      }));

      await request(app.getHttpServer())
        .post('/api/v1/internal/events/batch')
        .set('X-WAF-Ingest-Key', validIngestKey)
        .send({ events: eventsPayload })
        .expect(201);

      await jobQueue.drain();

      // Check notification created for Tenant A
      const notifRes = await request(app.getHttpServer())
        .get('/api/v1/notifications')
        .set('Cookie', `waf_access_token=${analystTokenA}`)
        .expect(200);

      expect(notifRes.body.total).toBeGreaterThanOrEqual(1);
      const spikeNotif = notifRes.body.items.find((n: any) => n.type === 'ATTACK_SPIKE');
      expect(spikeNotif).toBeDefined();
      expect(spikeNotif.severity).toBe('CRITICAL');

      // Check webhook was dispatched and signature is valid
      expect(httpSender.dispatched.length).toBeGreaterThanOrEqual(1);
      const dispatch = httpSender.dispatched[0];
      expect(dispatch.payload.eventType).toBe('ATTACK_SPIKE');
      expect(dispatch.signature).toMatch(/^sha256=/);
    });

    it('ingesting degradedMode: true triggers ML_DEGRADED warning notification', async () => {
      httpSender.clear();

      await request(app.getHttpServer())
        .post('/api/v1/internal/events')
        .set('X-WAF-Ingest-Key', validIngestKey)
        .send({
          tenantId: tenantIdA,
          siteId: siteIdA,
          requestId: 'req-deg-101',
          method: 'GET',
          path: '/search',
          action: 'MONITOR',
          degradedMode: true,
        })
        .expect(201);

      await jobQueue.drain();

      const notifRes = await request(app.getHttpServer())
        .get('/api/v1/notifications')
        .set('Cookie', `waf_access_token=${viewerTokenA}`)
        .expect(200);

      const degNotif = notifRes.body.items.find((n: any) => n.type === 'ML_DEGRADED');
      expect(degNotif).toBeDefined();
      expect(degNotif.severity).toBe('WARNING');
    });

    it('allows marking notification as read', async () => {
      const notifRes = await request(app.getHttpServer())
        .get('/api/v1/notifications')
        .set('Cookie', `waf_access_token=${viewerTokenA}`)
        .expect(200);

      const unread = notifRes.body.items[0];
      expect(unread.isRead).toBe(false);

      const readRes = await request(app.getHttpServer())
        .patch(`/api/v1/notifications/${unread.id}/read`)
        .set('Cookie', `waf_access_token=${analystTokenA}`)
        .expect(200);

      expect(readRes.body.isRead).toBe(true);
      expect(readRes.body.readAt).toBeDefined();
    });

    it('prevents Tenant B from reading or marking Tenant A notification (Cross-Tenant Isolation)', async () => {
      const notifRes = await request(app.getHttpServer())
        .get('/api/v1/notifications')
        .set('Cookie', `waf_access_token=${viewerTokenA}`)
        .expect(200);

      const notifA = notifRes.body.items[0];

      // Tenant B queries notifications -> sees 0
      const tenantBList = await request(app.getHttpServer())
        .get('/api/v1/notifications')
        .set('Cookie', `waf_access_token=${ownerTokenB}`)
        .expect(200);

      expect(tenantBList.body.items).toHaveLength(0);

      // Tenant B tries to mark Tenant A notification as read -> 404
      await request(app.getHttpServer())
        .patch(`/api/v1/notifications/${notifA.id}/read`)
        .set('Cookie', `waf_access_token=${ownerTokenB}`)
        .expect(404);
    });
  });

  describe('Policy Sync Worker & Policy Mutation Integration', () => {
    it('updating site policy enqueues policy-sync and syncs to gateway client', async () => {
      gatewayClient.clear();

      await request(app.getHttpServer())
        .put(`/api/v1/sites/${siteIdA}/policy`)
        .set('Cookie', `waf_access_token=${ownerTokenA}`)
        .send({
          name: 'Hardened Policy',
          mode: 'BLOCKING',
          blockThreshold: 0.80,
          challengeThreshold: 0.45,
          monitorThreshold: 0.05,
        })
        .expect(200);

      await jobQueue.drain();

      expect(gatewayClient.syncedPolicies).toHaveLength(1);
      expect(gatewayClient.syncedPolicies[0].siteId).toBe(siteIdA);
      expect(gatewayClient.syncedPolicies[0].policy.mode).toBe('BLOCKING');
      expect(gatewayClient.syncedPolicies[0].policy.version).toBe(2);
    });

    it('rolling back policy enqueues policy-sync to restore previous version', async () => {
      gatewayClient.clear();

      await request(app.getHttpServer())
        .post(`/api/v1/sites/${siteIdA}/policy/rollback/1`)
        .set('Cookie', `waf_access_token=${ownerTokenA}`)
        .expect(200);

      await jobQueue.drain();

      expect(gatewayClient.syncedPolicies).toHaveLength(1);
      expect(gatewayClient.syncedPolicies[0].siteId).toBe(siteIdA);
      expect(gatewayClient.syncedPolicies[0].policy.version).toBe(3);
    });
  });

  describe('Feedback Export Worker & ML Dataset Curation', () => {
    beforeEach(() => {
      dataProvider.clear();
      // Setup approved and unapproved feedback
      dataProvider.approvedFeedback = [
        {
          id: 'fb-app-1',
          tenantId: tenantIdA,
          securityEventId: 'evt-1',
          label: 'FALSE_POSITIVE',
          reviewStatus: 'APPROVED',
          notes: 'Legit webhook call',
          createdAt: new Date(),
          event: {
            method: 'POST',
            path: '/webhooks/stripe',
            riskScore: 0.88,
            action: 'BLOCK',
          },
        },
      ];
    });

    it('rejects feedback export trigger from ANALYST or VIEWER (403 Forbidden)', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/feedback/export')
        .set('Cookie', `waf_access_token=${analystTokenA}`)
        .expect(403);

      await request(app.getHttpServer())
        .post('/api/v1/feedback/export')
        .set('Cookie', `waf_access_token=${viewerTokenA}`)
        .expect(403);
    });

    it('accepts feedback export from ADMIN (202 Accepted) and creates FEEDBACK_EXPORT_READY notification', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/feedback/export')
        .set('Cookie', `waf_access_token=${adminTokenA}`)
        .expect(202);

      expect(res.body.jobId).toBeDefined();
      expect(res.body.status).toBe('QUEUED');

      await jobQueue.drain();

      // Check audit log was recorded
      expect(dataProvider.auditRecords).toHaveLength(1);
      expect(dataProvider.auditRecords[0].tenantId).toBe(tenantIdA);
      expect(dataProvider.auditRecords[0].metadata.recordCount).toBe(1);
      expect(dataProvider.auditRecords[0].metadata.sha256Digest).toBeDefined();

      // Check notification created
      const notifRes = await request(app.getHttpServer())
        .get('/api/v1/notifications')
        .set('Cookie', `waf_access_token=${adminTokenA}`)
        .expect(200);

      const exportNotif = notifRes.body.items.find((n: any) => n.type === 'FEEDBACK_EXPORT_READY');
      expect(exportNotif).toBeDefined();
      expect(exportNotif.severity).toBe('INFO');
      expect(exportNotif.metadata.recordCount).toBe(1);
    });

    it('Tenant B feedback export does NOT include Tenant A feedback records', async () => {
      dataProvider.clear();
      // Tenant B has 0 approved records
      const res = await request(app.getHttpServer())
        .post('/api/v1/feedback/export')
        .set('Cookie', `waf_access_token=${ownerTokenB}`)
        .expect(202);

      await jobQueue.drain();

      expect(dataProvider.auditRecords).toHaveLength(1);
      expect(dataProvider.auditRecords[0].tenantId).toBe(tenantIdB);
      expect(dataProvider.auditRecords[0].metadata.recordCount).toBe(0);
    });
  });
});
