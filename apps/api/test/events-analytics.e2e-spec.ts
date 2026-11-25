import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as cookieParser from 'cookie-parser';
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
import { TOKEN_SERVICE, ITokenService } from '../src/modules/identity/infrastructure/token.service';
import {
  WafAction,
  FeedbackLabel,
  FeedbackReviewStatus,
} from '../src/modules/security-events/domain/security-event.types';
import { UserRole } from '../src/modules/identity/domain/user-role';

describe('Phase 11 Security Events, Feedback Queue & Analytics (E2E)', () => {
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
  let tokenService: ITokenService;

  let ownerTokenA: string;
  let analystTokenA: string;
  let viewerTokenA: string;
  let ownerTokenB: string;
  let tenantIdA: string;
  let tenantIdB: string;
  let siteIdA: string;

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
    tokenService = app.get<ITokenService>(TOKEN_SERVICE);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Tenant & Site Setup', () => {
    it('sets up Tenant A and Tenant B with sites and RBAC credentials', async () => {
      // 1. Tenant A Owner
      const regResA = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@alpha-events.com',
          password: 'Password123!',
          tenantName: 'Alpha Events Corp',
          tenantSlug: 'alpha-events-corp',
        })
        .expect(201);

      ownerTokenA = regResA.body.accessToken;
      tenantIdA = regResA.body.activeTenantId;

      // Create site for Tenant A
      const siteRes = await request(app.getHttpServer())
        .post('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Alpha API Site',
          domain: 'api.alpha.com',
          originUrl: 'https://backend.alpha.local',
        })
        .expect(201);
      siteIdA = siteRes.body.id;

      // Add Analyst to Tenant A
      const analystRes = await request(app.getHttpServer())
        .post(`/api/v1/tenants/${tenantIdA}/members`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({ email: 'analyst@alpha-events.com', role: 'ANALYST' })
        .expect(201);

      analystTokenA = tokenService.generateAccessToken({
        sub: analystRes.body.userId,
        tenantId: tenantIdA,
        role: UserRole.ANALYST,
        email: 'analyst@alpha-events.com',
      });

      // Add Viewer to Tenant A
      const viewerRes = await request(app.getHttpServer())
        .post(`/api/v1/tenants/${tenantIdA}/members`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({ email: 'viewer@alpha-events.com', role: 'VIEWER' })
        .expect(201);

      viewerTokenA = tokenService.generateAccessToken({
        sub: viewerRes.body.userId,
        tenantId: tenantIdA,
        role: UserRole.VIEWER,
        email: 'viewer@alpha-events.com',
      });

      // 2. Tenant B Owner
      const regResB = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@beta-events.com',
          password: 'Password123!',
          tenantName: 'Beta Events Corp',
          tenantSlug: 'beta-events-corp',
        })
        .expect(201);

      ownerTokenB = regResB.body.accessToken;
      tenantIdB = regResB.body.activeTenantId;
    });
  });

  describe('Internal Gateway Event Ingestion (/api/v1/internal/events)', () => {
    it('rejects ingestion requests with missing or invalid X-WAF-Ingest-Key (401)', async () => {
      // Missing header
      await request(app.getHttpServer())
        .post('/api/v1/internal/events')
        .send({
          tenantId: tenantIdA,
          requestId: 'req-001',
          method: 'GET',
          path: '/api/v1/users',
          action: WafAction.ALLOW,
        })
        .expect(401);

      // Wrong key
      await request(app.getHttpServer())
        .post('/api/v1/internal/events')
        .set('X-WAF-Ingest-Key', 'wrong-secret')
        .send({
          tenantId: tenantIdA,
          requestId: 'req-001',
          method: 'GET',
          path: '/api/v1/users',
          action: WafAction.ALLOW,
        })
        .expect(401);
    });

    it('successfully ingests a single security event with sensitive fields sanitized (201)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/internal/events')
        .set('X-WAF-Ingest-Key', validIngestKey)
        .send({
          tenantId: tenantIdA,
          siteId: siteIdA,
          requestId: 'req-single-001',
          clientIpHash: 'hash-ip-123',
          method: 'POST',
          path: '/api/v1/login',
          action: WafAction.BLOCK,
          wouldAction: WafAction.BLOCK,
          reason: 'SQLi detected in password field',
          riskScore: 0.965,
          stageUsed: 'ml_layer2',
          ruleMatches: ['sqli_rule_01'],
          degradedMode: false,
          modelVersion: 'v1_0',
          policyVersion: 1,
          latencyMs: 14.5,
          redactedRequest: {
            headers: {
              authorization: 'Bearer secret-jwt-token',
              cookie: 'session=xyz123',
              host: 'api.alpha.com',
            },
            body: {
              username: 'admin',
              password: "' OR 1=1 --",
            },
          },
        })
        .expect(201);

      expect(res.body.ingested).toBe(1);
      expect(res.body.ids.length).toBe(1);

      // Verify event was saved and sensitive fields sanitized
      const saved = await eventRepo.findById(tenantIdA, res.body.ids[0]);
      expect(saved).toBeDefined();
      expect(saved?.action).toBe(WafAction.BLOCK);
      expect(saved?.redactedRequest.headers.authorization).toBe('[REDACTED]');
      expect(saved?.redactedRequest.headers.cookie).toBe('[REDACTED]');
      expect(saved?.redactedRequest.body.password).toBe('[REDACTED]');
      expect(saved?.redactedRequest.body.username).toBe('admin');
    });

    it('successfully ingests a batch of events (up to 100) (201)', async () => {
      const batchPayload = [
        {
          tenantId: tenantIdA,
          siteId: siteIdA,
          requestId: 'req-batch-001',
          method: 'GET',
          path: '/api/v1/products',
          action: WafAction.ALLOW,
          riskScore: 0.02,
          latencyMs: 3.2,
        },
        {
          tenantId: tenantIdA,
          siteId: siteIdA,
          requestId: 'req-batch-002',
          method: 'GET',
          path: '/api/v1/search?q=test',
          action: WafAction.CHALLENGE,
          riskScore: 0.62,
          latencyMs: 6.8,
          reason: 'High request frequency in search',
        },
        {
          tenantId: tenantIdA,
          siteId: siteIdA,
          requestId: 'req-batch-003',
          method: 'POST',
          path: '/api/v1/checkout',
          action: WafAction.MONITOR,
          riskScore: 0.15,
          latencyMs: 4.1,
          degradedMode: true,
        },
        // Also ingest an event for Tenant B to test isolation
        {
          tenantId: tenantIdB,
          requestId: 'req-batch-tenant-b-001',
          method: 'POST',
          path: '/secret-portal',
          action: WafAction.BLOCK,
          riskScore: 0.99,
          latencyMs: 12.0,
        },
      ];

      const res = await request(app.getHttpServer())
        .post('/api/v1/internal/events/batch')
        .set('X-WAF-Ingest-Key', validIngestKey)
        .send({ events: batchPayload })
        .expect(201);

      expect(res.body.ingested).toBe(4);
      expect(res.body.ids.length).toBe(4);
    });
  });

  describe('Security Events Querying & Filtering (/api/v1/events)', () => {
    it('lists events for Tenant A with pagination and total count', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .expect(200);

      expect(res.body.items).toBeDefined();
      expect(res.body.total).toBe(4); // 1 single + 3 batch for Tenant A
      expect(res.body.page).toBe(1);
      expect(res.body.limit).toBe(20);
    });

    it('filters events by action (BLOCK)', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/events?action=BLOCK')
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .expect(200);

      expect(res.body.items.length).toBe(1);
      expect(res.body.items[0].action).toBe('BLOCK');
      expect(res.body.items[0].requestId).toBe('req-single-001');
    });

    it('filters events by minRiskScore', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/events?minRiskScore=0.60')
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .expect(200);

      expect(res.body.items.length).toBe(2); // 0.965 and 0.62
    });

    it('filters events by pathContains', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/events?pathContains=search')
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .expect(200);

      expect(res.body.items.length).toBe(1);
      expect(res.body.items[0].path).toContain('search');
    });

    it('gets security event details by ID', async () => {
      const listRes = await request(app.getHttpServer())
        .get('/api/v1/events?action=BLOCK')
        .set('Authorization', `Bearer ${viewerTokenA}`);
      const eventId = listRes.body.items[0].id;

      const res = await request(app.getHttpServer())
        .get(`/api/v1/events/${eventId}`)
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .expect(200);

      expect(res.body.id).toBe(eventId);
      expect(res.body.action).toBe('BLOCK');
      expect(res.body.requestId).toBe('req-single-001');
    });
  });

  describe('False-Positive Feedback Queue & Review Lifecycle (/api/v1/feedback)', () => {
    let blockedEventId: string;
    let feedbackId: string;

    beforeAll(async () => {
      const listRes = await request(app.getHttpServer())
        .get('/api/v1/events?action=BLOCK')
        .set('Authorization', `Bearer ${ownerTokenA}`);
      blockedEventId = listRes.body.items[0].id;
    });

    it('rejects feedback submission by VIEWER (403 Forbidden)', async () => {
      await request(app.getHttpServer())
        .post(`/api/v1/events/${blockedEventId}/feedback`)
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .send({
          label: FeedbackLabel.FALSE_POSITIVE,
          notes: 'Viewer attempting to submit feedback',
        })
        .expect(403);
    });

    it('allows ANALYST to submit False-Positive feedback (201 Created)', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/events/${blockedEventId}/feedback`)
        .set('Authorization', `Bearer ${analystTokenA}`)
        .send({
          label: FeedbackLabel.FALSE_POSITIVE,
          notes: 'Customer reported login blocked on legitimate password pattern',
        })
        .expect(201);

      expect(res.body.id).toBeDefined();
      expect(res.body.securityEventId).toBe(blockedEventId);
      expect(res.body.label).toBe('FALSE_POSITIVE');
      expect(res.body.reviewStatus).toBe('PENDING_REVIEW');
      expect(res.body.reviewerUserId).toBeNull();

      feedbackId = res.body.id;

      // Verify Audit Log recorded
      const logs = await auditRepo.findByTenant(tenantIdA);
      const audit = logs.find((l) => l.action === 'EVENT_FEEDBACK_SUBMITTED');
      expect(audit).toBeDefined();
      expect(audit?.resourceId).toBe(feedbackId);
    });

    it('lists feedback queue items for active tenant', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/feedback?reviewStatus=PENDING_REVIEW')
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .expect(200);

      expect(res.body.items.length).toBe(1);
      expect(res.body.items[0].id).toBe(feedbackId);
      expect(res.body.items[0].reviewStatus).toBe('PENDING_REVIEW');
    });

    it('rejects feedback review by ANALYST or VIEWER (403 Forbidden)', async () => {
      await request(app.getHttpServer())
        .patch(`/api/v1/feedback/${feedbackId}/review`)
        .set('Authorization', `Bearer ${analystTokenA}`)
        .send({
          status: FeedbackReviewStatus.APPROVED,
          reviewNotes: 'Analyst trying to approve',
        })
        .expect(403);

      await request(app.getHttpServer())
        .patch(`/api/v1/feedback/${feedbackId}/review`)
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .send({
          status: FeedbackReviewStatus.APPROVED,
        })
        .expect(403);
    });

    it('allows OWNER to review and APPROVE feedback (200 OK)', async () => {
      const res = await request(app.getHttpServer())
        .patch(`/api/v1/feedback/${feedbackId}/review`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          status: FeedbackReviewStatus.APPROVED,
          reviewNotes: 'Verified False Positive. Pattern queued for offline dataset review.',
        })
        .expect(200);

      expect(res.body.reviewStatus).toBe('APPROVED');
      expect(res.body.reviewerUserId).toBeDefined();
      expect(res.body.reviewNotes).toContain('Verified False Positive');
      expect(res.body.reviewedAt).toBeDefined();

      // Verify Audit Log recorded
      const logs = await auditRepo.findByTenant(tenantIdA);
      const audit = logs.find((l) => l.action === 'EVENT_FEEDBACK_REVIEWED');
      expect(audit).toBeDefined();
      expect(audit?.resourceId).toBe(feedbackId);
    });

    it('rejects second review on already finalized feedback (400 Bad Request)', async () => {
      await request(app.getHttpServer())
        .patch(`/api/v1/feedback/${feedbackId}/review`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          status: FeedbackReviewStatus.REJECTED,
          reviewNotes: 'Attempting to change decision',
        })
        .expect(400);
    });
  });

  describe('Cross-Tenant Security Isolation (CRITICAL)', () => {
    let tenantAEventId: string;
    let tenantAFeedbackId: string;

    beforeAll(async () => {
      const listEventsA = await request(app.getHttpServer())
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${ownerTokenA}`);
      tenantAEventId = listEventsA.body.items[0].id;

      const listFeedbackA = await request(app.getHttpServer())
        .get('/api/v1/feedback')
        .set('Authorization', `Bearer ${ownerTokenA}`);
      tenantAFeedbackId = listFeedbackA.body.items[0].id;
    });

    it('Tenant B sees ONLY its own events when querying /events', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/events')
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .expect(200);

      expect(res.body.total).toBe(1);
      expect(res.body.items[0].requestId).toBe('req-batch-tenant-b-001');
      expect(res.body.items[0].path).toBe('/secret-portal');
    });

    it('Tenant B receives 404 Not Found trying to access Tenant A event by ID', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/events/${tenantAEventId}`)
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .expect(404);
    });

    it('Tenant B receives 404 Not Found trying to submit feedback on Tenant A event', async () => {
      await request(app.getHttpServer())
        .post(`/api/v1/events/${tenantAEventId}/feedback`)
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .send({
          label: FeedbackLabel.FALSE_POSITIVE,
        })
        .expect(404);
    });

    it('Tenant B receives 404 Not Found trying to review Tenant A feedback item', async () => {
      await request(app.getHttpServer())
        .patch(`/api/v1/feedback/${tenantAFeedbackId}/review`)
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .send({
          status: FeedbackReviewStatus.APPROVED,
        })
        .expect(404);
    });
  });

  describe('Analytics Endpoints (/api/v1/analytics)', () => {
    it('returns overview metrics strictly scoped to Tenant A', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/analytics/overview?window=24h')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(res.body.window).toBe('24h');
      expect(res.body.metrics.totalRequests).toBe(4);
      expect(res.body.metrics.blockedCount).toBe(1);
      expect(res.body.metrics.challengedCount).toBe(1);
      expect(res.body.metrics.monitoredCount).toBe(1);
      expect(res.body.metrics.allowedCount).toBe(1);
      expect(res.body.metrics.blockRatePct).toBe(25.0);
      expect(res.body.metrics.degradedCount).toBe(1);
      expect(res.body.metrics.p50LatencyMs).toBeGreaterThan(0);
      expect(res.body.metrics.p95LatencyMs).toBeGreaterThan(0);
    });

    it('returns timeseries buckets strictly scoped to Tenant A', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/analytics/timeseries?window=24h')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(res.body.window).toBe('24h');
      expect(Array.isArray(res.body.buckets)).toBe(true);
      expect(res.body.buckets.length).toBeGreaterThan(0);
      expect(res.body.buckets[0].bucket).toBeDefined();
      expect(res.body.buckets[0].total).toBeGreaterThan(0);
    });

    it('returns top attacked paths and trigger reasons strictly scoped to Tenant A', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/analytics/top-threats?window=24h&limit=5')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(Array.isArray(res.body.topPaths)).toBe(true);
      expect(res.body.topPaths.length).toBeGreaterThan(0);
      expect(res.body.topPaths[0].path).toBeDefined();

      expect(Array.isArray(res.body.topReasons)).toBe(true);
      expect(res.body.topReasons.length).toBeGreaterThan(0);
      expect(res.body.topReasons[0].reason).toContain('SQLi');
    });

    it('confirms Tenant B analytics overview NEVER leaks Tenant A metrics', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/analytics/overview?window=24h')
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .expect(200);

      expect(res.body.metrics.totalRequests).toBe(1);
      expect(res.body.metrics.blockedCount).toBe(1);
      expect(res.body.metrics.blockRatePct).toBe(100.0);
    });
  });
});
