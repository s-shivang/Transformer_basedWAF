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
import { DNS_VERIFIER } from '../src/modules/protected-sites/domain/dns-verifier.interface';
import { LocalDevDnsVerifier } from '../src/modules/protected-sites/infrastructure/dns/local-dev-dns.verifier';
import { SITE_CONFIG_SYNC_CLIENT } from '../src/modules/protected-sites/domain/site-config-sync.interface';
import { InMemorySiteConfigSyncClient } from '../src/modules/protected-sites/infrastructure/gateway/in-memory-site-config-sync.client';
import { TOKEN_SERVICE, ITokenService } from '../src/modules/identity/infrastructure/token.service';
import { UserRole } from '../src/modules/identity/domain/user-role';

describe('Phase 17A Site Onboarding & Domain Verification (E2E)', () => {
  let app: INestApplication;
  let tenantRepo: InMemoryTenantRepository;
  let userRepo: InMemoryUserRepository;
  let memberRepo: InMemoryMembershipRepository;
  let sessionRepo: InMemoryRefreshSessionRepository;
  let auditRepo: InMemoryAuditLogRepository;
  let siteRepo: InMemoryProtectedSiteRepository;
  let policyRepo: InMemoryWafPolicyRepository;
  let dnsVerifier: LocalDevDnsVerifier;
  let syncClient: InMemorySiteConfigSyncClient;
  let tokenService: ITokenService;

  let ownerTokenA: string;
  let analystTokenA: string;
  let viewerTokenA: string;
  let ownerTokenB: string;
  let tenantIdA: string;
  let tenantIdB: string;

  beforeAll(async () => {
    tenantRepo = new InMemoryTenantRepository();
    userRepo = new InMemoryUserRepository();
    memberRepo = new InMemoryMembershipRepository();
    sessionRepo = new InMemoryRefreshSessionRepository();
    auditRepo = new InMemoryAuditLogRepository();
    siteRepo = new InMemoryProtectedSiteRepository();
    policyRepo = new InMemoryWafPolicyRepository();
    dnsVerifier = new LocalDevDnsVerifier();
    syncClient = new InMemorySiteConfigSyncClient();

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
      .overrideProvider(DNS_VERIFIER)
      .useValue(dnsVerifier)
      .overrideProvider(SITE_CONFIG_SYNC_CLIENT)
      .useValue(syncClient)
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

  describe('1. Setup Tenants and RBAC Tokens', () => {
    it('provisions Tenant A and Tenant B with appropriate roles', async () => {
      // Register Tenant A Owner
      const regResA = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@onboarding-a.com',
          password: 'Password123!',
          tenantName: 'Onboarding Tenant A',
          tenantSlug: 'onboarding-tenant-a',
        })
        .expect(201);

      ownerTokenA = regResA.body.accessToken;
      tenantIdA = regResA.body.activeTenantId;

      // Add Analyst in Tenant A
      const analystRes = await request(app.getHttpServer())
        .post(`/api/v1/tenants/${tenantIdA}/members`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({ email: 'analyst@onboarding-a.com', role: 'ANALYST' })
        .expect(201);

      analystTokenA = tokenService.generateAccessToken({
        sub: analystRes.body.userId,
        email: 'analyst@onboarding-a.com',
        tenantId: tenantIdA,
        role: UserRole.ANALYST,
      });

      // Add Viewer in Tenant A
      const viewerRes = await request(app.getHttpServer())
        .post(`/api/v1/tenants/${tenantIdA}/members`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({ email: 'viewer@onboarding-a.com', role: 'VIEWER' })
        .expect(201);

      viewerTokenA = tokenService.generateAccessToken({
        sub: viewerRes.body.userId,
        email: 'viewer@onboarding-a.com',
        tenantId: tenantIdA,
        role: UserRole.VIEWER,
      });

      // Register Tenant B Owner
      const regResB = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@onboarding-b.com',
          password: 'Password123!',
          tenantName: 'Onboarding Tenant B',
          tenantSlug: 'onboarding-tenant-b',
        })
        .expect(201);

      ownerTokenB = regResB.body.accessToken;
      tenantIdB = regResB.body.activeTenantId;
    });
  });

  describe('2. Tenant Site Quota Controls (PATCH /api/v1/tenants/:id/quota)', () => {
    it('allows OWNER to update site quota limit', async () => {
      const res = await request(app.getHttpServer())
        .patch(`/api/v1/tenants/${tenantIdA}/quota`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({ maxSites: 2 })
        .expect(200);

      expect(res.body.maxSites).toBe(2);
    });

    it('rejects ANALYST attempt to modify quota with 403 Forbidden', async () => {
      await request(app.getHttpServer())
        .patch(`/api/v1/tenants/${tenantIdA}/quota`)
        .set('Authorization', `Bearer ${analystTokenA}`)
        .send({ maxSites: 10 })
        .expect(403);
    });

    it('rejects invalid quota bounds (< 1 or > 100) with 400 Bad Request', async () => {
      await request(app.getHttpServer())
        .patch(`/api/v1/tenants/${tenantIdA}/quota`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({ maxSites: 0 })
        .expect(400);

      await request(app.getHttpServer())
        .patch(`/api/v1/tenants/${tenantIdA}/quota`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({ maxSites: 105 })
        .expect(400);
    });
  });

  describe('3. Onboarding Initiation & Quota Enforcement', () => {
    let siteId1: string;

    it('starts onboarding for site 1 in PENDING_VERIFICATION state', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/sites/onboarding')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Primary API Gateway',
          domain: 'api.acme-onboarding.com',
          originUrl: 'https://backend.internal.acme:8443',
        })
        .expect(201);

      siteId1 = res.body.siteId;
      expect(siteId1).toBeDefined();
      expect(res.body.onboardingStatus).toBe('PENDING_VERIFICATION');
      expect(res.body.verificationToken).toMatch(/^waf-verify-[a-f0-9]{32}$/);
      expect(res.body.txtRecord.host).toBe('_waf-challenge.api.acme-onboarding.com');
      expect(res.body.txtRecord.value).toBe(res.body.verificationToken);
    });

    it('starts onboarding for site 2 successfully (quota = 2)', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/sites/onboarding')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Storefront Web',
          domain: 'store.acme-onboarding.com',
          originUrl: 'https://store-backend.internal:443',
        })
        .expect(201);
    });

    it('rejects site 3 with 400 Bad Request when tenant quota is exceeded', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/sites/onboarding')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Exceeding Site',
          domain: 'blog.acme-onboarding.com',
          originUrl: 'https://blog.internal:443',
        })
        .expect(400);

      expect(res.body.message).toContain('quota limit reached');
    });

    it('rejects cross-tenant domain hijacking with 409 Conflict', async () => {
      // Tenant B tries to claim api.acme-onboarding.com owned by Tenant A
      const res = await request(app.getHttpServer())
        .post('/api/v1/sites/onboarding')
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .send({
          name: 'Hijacked API',
          domain: 'api.acme-onboarding.com',
          originUrl: 'https://malicious.upstream:443',
        })
        .expect(409);

      expect(res.body.message).toContain('already claimed');
    });
  });

  describe('4. DNS Instructions & Domain Ownership Verification', () => {
    let siteId: string;
    let verificationToken: string;

    beforeAll(async () => {
      // Expand quota to 5 to allow more tests
      await request(app.getHttpServer())
        .patch(`/api/v1/tenants/${tenantIdA}/quota`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({ maxSites: 5 })
        .expect(200);

      const res = await request(app.getHttpServer())
        .post('/api/v1/sites/onboarding')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Auth Gateway',
          domain: 'auth.acme-onboarding.com',
          originUrl: 'https://auth-node.internal:8080',
        })
        .expect(201);

      siteId = res.body.siteId;
      verificationToken = res.body.verificationToken;
    });

    it('allows VIEWER to inspect onboarding instructions', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/sites/${siteId}/onboarding`)
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .expect(200);

      expect(res.body.siteId).toBe(siteId);
      expect(res.body.onboardingStatus).toBe('PENDING_VERIFICATION');
      expect(res.body.verificationToken).toBe(verificationToken);
    });

    it('fails domain verification when DNS record is missing and marks site FAILED', async () => {
      dnsVerifier.clear();

      const res = await request(app.getHttpServer())
        .post(`/api/v1/sites/${siteId}/onboarding/verify-domain`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(400);

      // Check status transitioned to FAILED
      const getRes = await request(app.getHttpServer())
        .get(`/api/v1/sites/${siteId}/onboarding`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(getRes.body.onboardingStatus).toBe('FAILED');
      expect(getRes.body.lastError).toBeDefined();
    });

    it('allows retrying onboarding from FAILED state', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/sites/${siteId}/onboarding/retry`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({})
        .expect(200);

      expect(res.body.onboardingStatus).toBe('PENDING_VERIFICATION');
    });

    it('verifies domain successfully when DNS TXT record matches and transitions to VERIFIED', async () => {
      dnsVerifier.registerTxtRecord('auth.acme-onboarding.com', verificationToken);

      const res = await request(app.getHttpServer())
        .post(`/api/v1/sites/${siteId}/onboarding/verify-domain`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(res.body.verified).toBe(true);
      expect(res.body.site.onboardingStatus).toBe('VERIFIED');
      expect(res.body.site.verifiedAt).toBeDefined();
    });
  });

  describe('5. Site Pause and Resume Operations', () => {
    let activeSiteId: string;

    beforeAll(async () => {
      // Create via legacy endpoint (immediately ACTIVE)
      const res = await request(app.getHttpServer())
        .post('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Active Service',
          domain: 'active.acme-onboarding.com',
          originUrl: 'https://active.internal:443',
        })
        .expect(201);

      activeSiteId = res.body.id;
    });

    it('pauses an active site', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/sites/${activeSiteId}/onboarding/pause`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(res.body.onboardingStatus).toBe('PAUSED');
    });

    it('resumes a paused site', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/sites/${activeSiteId}/onboarding/resume`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(res.body.onboardingStatus).toBe('ACTIVE');
    });
  });

  describe('6. Phase 17B Atomic Gateway Configuration Sync', () => {
    let verifiedSiteId: string;
    let pendingSiteId: string;

    beforeAll(async () => {
      // Expand quota to 10 for Phase 17B tests
      await request(app.getHttpServer())
        .patch(`/api/v1/tenants/${tenantIdA}/quota`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({ maxSites: 10 })
        .expect(200);

      // 1. Create a site in PENDING_VERIFICATION
      const pendingRes = await request(app.getHttpServer())
        .post('/api/v1/sites/onboarding')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Pending Sync Test',
          domain: 'pending-sync.acme-onboarding.com',
          originUrl: 'https://pending.internal:443',
        })
        .expect(201);
      pendingSiteId = pendingRes.body.siteId;

      // 2. Create another site and verify domain
      const verifiedRes = await request(app.getHttpServer())
        .post('/api/v1/sites/onboarding')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Verified Sync Test',
          domain: 'verified-sync.acme-onboarding.com',
          originUrl: 'https://verified.internal:443',
        })
        .expect(201);
      verifiedSiteId = verifiedRes.body.siteId;

      dnsVerifier.registerTxtRecord(
        'verified-sync.acme-onboarding.com',
        verifiedRes.body.verificationToken,
      );

      await request(app.getHttpServer())
        .post(`/api/v1/sites/${verifiedSiteId}/onboarding/verify-domain`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);
    });

    it('rejects gateway configure on unverified site with 400 Bad Request', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/sites/${pendingSiteId}/onboarding/configure`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({})
        .expect(400);

      expect(res.body.message).toContain('Site must be VERIFIED');
    });

    it('rejects cross-tenant configure with 404 Not Found', async () => {
      await request(app.getHttpServer())
        .post(`/api/v1/sites/${verifiedSiteId}/onboarding/configure`)
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .send({})
        .expect(404);
    });

    it('pushes configuration to gateway atomically and transitions VERIFIED -> DNS_PENDING', async () => {
      syncClient.clear();

      const res = await request(app.getHttpServer())
        .post(`/api/v1/sites/${verifiedSiteId}/onboarding/configure`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({})
        .expect(200);

      expect(res.body.onboardingStatus).toBe('DNS_PENDING');
      expect(res.body.gatewayAckVersion).toBe(res.body.configVersion);
      expect(res.body.lastSyncedAt).toBeDefined();

      // Check sync client received the payload
      expect(syncClient.syncedConfigs.has('verified-sync.acme-onboarding.com')).toBe(true);
      const synced = syncClient.syncedConfigs.get('verified-sync.acme-onboarding.com');
      expect(synced?.site_id).toBe(verifiedSiteId);
      expect(synced?.origin_url).toBe('https://verified.internal:443');
    });

    it('transitions to FAILED when gateway sync returns error', async () => {
      syncClient.setShouldFail(true, 'Gateway connection timeout');

      const res = await request(app.getHttpServer())
        .post(`/api/v1/sites/${verifiedSiteId}/onboarding/configure`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({})
        .expect(400);

      expect(res.body.message).toContain('Gateway connection timeout');

      // Check site status transitioned to FAILED
      const getRes = await request(app.getHttpServer())
        .get(`/api/v1/sites/${verifiedSiteId}/onboarding`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(getRes.body.onboardingStatus).toBe('FAILED');
      expect(getRes.body.lastError).toContain('Gateway connection timeout');
    });
  });
});
