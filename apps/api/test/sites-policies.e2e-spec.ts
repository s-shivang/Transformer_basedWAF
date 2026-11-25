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
import { TOKEN_SERVICE, ITokenService } from '../src/modules/identity/infrastructure/token.service';
import { WafMode } from '../src/modules/waf-policies/domain/waf-policy.entity';
import { UserRole } from '../src/modules/identity/domain/user-role';

describe('Phase 10 Protected Sites & WAF Policies Management (E2E)', () => {
  let app: INestApplication;
  let tenantRepo: InMemoryTenantRepository;
  let userRepo: InMemoryUserRepository;
  let memberRepo: InMemoryMembershipRepository;
  let sessionRepo: InMemoryRefreshSessionRepository;
  let auditRepo: InMemoryAuditLogRepository;
  let siteRepo: InMemoryProtectedSiteRepository;
  let policyRepo: InMemoryWafPolicyRepository;
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

  describe('Tenant Onboarding & RBAC Setup', () => {
    it('sets up Tenant A with Owner, Analyst, and Viewer', async () => {
      // 1. Register Owner for Tenant A
      const regResA = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@tenant-a.com',
          password: 'Password123!',
          tenantName: 'Tenant A Corp',
          tenantSlug: 'tenant-a-corp',
        })
        .expect(201);

      ownerTokenA = regResA.body.accessToken;
      tenantIdA = regResA.body.activeTenantId;
      expect(ownerTokenA).toBeDefined();

      // 2. Add Analyst to Tenant A
      const analystMemberRes = await request(app.getHttpServer())
        .post(`/api/v1/tenants/${tenantIdA}/members`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          email: 'analyst@tenant-a.com',
          role: 'ANALYST',
        })
        .expect(201);

      analystTokenA = tokenService.generateAccessToken({
        sub: analystMemberRes.body.userId,
        tenantId: tenantIdA,
        role: UserRole.ANALYST,
        email: 'analyst@tenant-a.com',
      });

      // 3. Add Viewer to Tenant A
      const viewerMemberRes = await request(app.getHttpServer())
        .post(`/api/v1/tenants/${tenantIdA}/members`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          email: 'viewer@tenant-a.com',
          role: 'VIEWER',
        })
        .expect(201);

      viewerTokenA = tokenService.generateAccessToken({
        sub: viewerMemberRes.body.userId,
        tenantId: tenantIdA,
        role: UserRole.VIEWER,
        email: 'viewer@tenant-a.com',
      });

      // 4. Register Tenant B Owner
      const regResB = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@tenant-b.com',
          password: 'Password123!',
          tenantName: 'Tenant B Corp',
          tenantSlug: 'tenant-b-corp',
        })
        .expect(201);

      ownerTokenB = regResB.body.accessToken;
      tenantIdB = regResB.body.activeTenantId;
      expect(ownerTokenB).toBeDefined();
    });
  });

  describe('Protected Sites Management & Auto-Provisioned v1 Policy', () => {
    let createdSiteId: string;

    it('rejects site creation with invalid domain formats (e.g. scheme, wildcard)', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Bad Domain Site',
          domain: 'https://api.example.com',
          originUrl: 'https://backend.example.com',
        })
        .expect(400);

      await request(app.getHttpServer())
        .post('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Wildcard Site',
          domain: '*.example.com',
          originUrl: 'https://backend.example.com',
        })
        .expect(400);
    });

    it('rejects site creation with SSRF origin host (169.254.169.254)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'SSRF Attack Site',
          domain: 'attack.example.com',
          originUrl: 'http://169.254.169.254/latest/meta-data/',
        })
        .expect(400);

      expect(res.body.message).toContain('Forbidden origin host');
    });

    it('creates protected site and auto-provisions default v1 MONITOR policy', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Alpha Customer Portal',
          domain: 'portal.tenant-a.com',
          originUrl: 'https://internal-portal.tenant-a.aws.local:8443',
        })
        .expect(201);

      expect(res.body.id).toBeDefined();
      expect(res.body.domain).toBe('portal.tenant-a.com');
      expect(res.body.status).toBe('ACTIVE');
      expect(res.body.defaultPolicyVersion).toBe(1);

      createdSiteId = res.body.id;

      // Verify Audit Log was recorded
      const logs = await auditRepo.findByTenant(tenantIdA);
      const siteCreatedLog = logs.find((l) => l.action === 'SITE_CREATED');
      expect(siteCreatedLog).toBeDefined();
      expect(siteCreatedLog?.resourceId).toBe(createdSiteId);
    });

    it('rejects duplicate domain registration within same tenant', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Duplicate Portal',
          domain: 'portal.tenant-a.com',
          originUrl: 'https://other-origin.local',
        })
        .expect(409);

      expect(res.body.message).toContain('already exists');
    });

    it('lists protected sites for the authenticated tenant', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBe(1);
      expect(res.body[0].domain).toBe('portal.tenant-a.com');
    });

    it('gets protected site by id', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/sites/${createdSiteId}`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(res.body.id).toBe(createdSiteId);
      expect(res.body.name).toBe('Alpha Customer Portal');
    });

    it('updates site name and origin url', async () => {
      const res = await request(app.getHttpServer())
        .patch(`/api/v1/sites/${createdSiteId}`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Alpha Customer Portal v2',
          originUrl: 'https://updated-portal.tenant-a.aws.local:8443',
        })
        .expect(200);

      expect(res.body.name).toBe('Alpha Customer Portal v2');
      expect(res.body.originUrl).toBe('https://updated-portal.tenant-a.aws.local:8443');
    });

    it('confirms auto-provisioned policy is v1, MONITOR mode, with safe thresholds', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/sites/${createdSiteId}/policy`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(res.body.version).toBe(1);
      expect(res.body.mode).toBe(WafMode.MONITOR);
      expect(res.body.isActive).toBe(true);
      expect(res.body.thresholds.monitorThreshold).toBe(0.05);
      expect(res.body.thresholds.challengeThreshold).toBe(0.50);
      expect(res.body.thresholds.blockThreshold).toBe(0.85);
      expect(res.body.exclusions).toEqual([]);
    });
  });

  describe('WAF Policy Customization, Versioning & Scoped Exclusions', () => {
    let siteId: string;

    beforeAll(async () => {
      const list = await request(app.getHttpServer())
        .get('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`);
      siteId = list.body[0].id;
    });

    it('rejects policy update with invalid thresholds (challenge <= monitor)', async () => {
      await request(app.getHttpServer())
        .put(`/api/v1/sites/${siteId}/policy`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          monitorThreshold: 0.60,
          challengeThreshold: 0.50,
          blockThreshold: 0.85,
        })
        .expect(400);
    });

    it('rejects policy update with broad wildcard exclusions (* or /*)', async () => {
      await request(app.getHttpServer())
        .put(`/api/v1/sites/${siteId}/policy`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          exclusions: [
            {
              pathPrefix: '/*',
              reason: 'Bypass all traffic across site',
            },
          ],
        })
        .expect(400);
    });

    it('updates policy to v2 BLOCKING with scoped exclusion and customized thresholds', async () => {
      const res = await request(app.getHttpServer())
        .put(`/api/v1/sites/${siteId}/policy`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .send({
          name: 'Stricter Production Policy',
          mode: WafMode.BLOCKING,
          monitorThreshold: 0.08,
          challengeThreshold: 0.60,
          blockThreshold: 0.90,
          exclusions: [
            {
              pathPrefix: '/api/v1/webhooks',
              parameterName: 'payload',
              reason: 'Third party webhook sends base64 SQL-like payloads',
              skipMl: true,
              skipRules: false,
            },
          ],
        })
        .expect(200);

      expect(res.body.version).toBe(2);
      expect(res.body.mode).toBe(WafMode.BLOCKING);
      expect(res.body.thresholds.monitorThreshold).toBe(0.08);
      expect(res.body.thresholds.challengeThreshold).toBe(0.60);
      expect(res.body.thresholds.blockThreshold).toBe(0.90);
      expect(res.body.exclusions.length).toBe(1);
      expect(res.body.exclusions[0].pathPrefix).toBe('/api/v1/webhooks');

      // Check audit log
      const logs = await auditRepo.findByTenant(tenantIdA);
      const updateLog = logs.find((l) => l.action === 'WAF_POLICY_UPDATED');
      expect(updateLog).toBeDefined();
      expect(updateLog?.metadata.newVersion).toBe(2);
    });

    it('lists policy history showing v2 active and v1 archived', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/sites/${siteId}/policy/history`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(res.body.length).toBe(2);
      expect(res.body[0].version).toBe(2);
      expect(res.body[0].isActive).toBe(true);
      expect(res.body[1].version).toBe(1);
      expect(res.body[1].isActive).toBe(false);
    });

    it('performs 1-click rollback: restoring v1 settings as a new active version v3', async () => {
      const res = await request(app.getHttpServer())
        .post(`/api/v1/sites/${siteId}/policy/rollback/1`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(res.body.version).toBe(3);
      expect(res.body.mode).toBe(WafMode.MONITOR);
      expect(res.body.thresholds.monitorThreshold).toBe(0.05);
      expect(res.body.thresholds.challengeThreshold).toBe(0.50);
      expect(res.body.thresholds.blockThreshold).toBe(0.85);
      expect(res.body.exclusions).toEqual([]);
      expect(res.body.name).toContain('Rollback to v1');

      // Check audit log
      const logs = await auditRepo.findByTenant(tenantIdA);
      const rollbackLog = logs.find((l) => l.action === 'WAF_POLICY_ROLLED_BACK');
      expect(rollbackLog).toBeDefined();
      expect(rollbackLog?.metadata.rolledBackToVersion).toBe(1);
      expect(rollbackLog?.metadata.newVersion).toBe(3);

      // Verify history now has 3 versions
      const historyRes = await request(app.getHttpServer())
        .get(`/api/v1/sites/${siteId}/policy/history`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(historyRes.body.length).toBe(3);
      expect(historyRes.body[0].version).toBe(3);
      expect(historyRes.body[0].isActive).toBe(true);
      expect(historyRes.body[1].version).toBe(2);
      expect(historyRes.body[1].isActive).toBe(false);
      expect(historyRes.body[2].version).toBe(1);
      expect(historyRes.body[2].isActive).toBe(false);
    });

    it('provides effective gateway policy formatted for Python WAF Data Plane', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/sites/${siteId}/policy/effective`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      expect(res.body.siteId).toBe(siteId);
      expect(res.body.domain).toBe('portal.tenant-a.com');
      expect(res.body.mode).toBe(WafMode.MONITOR);
      expect(res.body.policyVersion).toBe(3);
      expect(res.body.ml_enabled).toBe(true);
      expect(res.body.rules_enabled).toBe(true);
      expect(res.body.challenge_enabled).toBe(true);
      expect(res.body.thresholds).toEqual({
        fast_pass_allow: 0.04,
        monitor_alert: 0.05,
        challenge: 0.50,
        block: 0.85,
      });
      expect(Array.isArray(res.body.exclusions)).toBe(true);
    });
  });

  describe('Cross-Tenant Data Isolation (Tenant B vs Tenant A)', () => {
    let siteIdA: string;

    beforeAll(async () => {
      const listA = await request(app.getHttpServer())
        .get('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`);
      siteIdA = listA.body[0].id;
    });

    it('Tenant B sees 0 sites when listing sites', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .expect(200);

      expect(res.body).toEqual([]);
    });

    it('Tenant B receives 404 Not Found when attempting to read Tenant A site', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/sites/${siteIdA}`)
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .expect(404);
    });

    it('Tenant B receives 404 Not Found when attempting to modify Tenant A site', async () => {
      await request(app.getHttpServer())
        .patch(`/api/v1/sites/${siteIdA}`)
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .send({ name: 'Hacked Site Name' })
        .expect(404);
    });

    it('Tenant B receives 404 Not Found when attempting to read Tenant A policy', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/sites/${siteIdA}/policy`)
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .expect(404);
    });

    it('Tenant B receives 404 Not Found when attempting to update Tenant A policy', async () => {
      await request(app.getHttpServer())
        .put(`/api/v1/sites/${siteIdA}/policy`)
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .send({ mode: WafMode.DISABLED })
        .expect(404);
    });

    it('Tenant B receives 404 Not Found when attempting to rollback Tenant A policy', async () => {
      await request(app.getHttpServer())
        .post(`/api/v1/sites/${siteIdA}/policy/rollback/1`)
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .expect(404);
    });

    it('Tenant B receives 404 Not Found when attempting to delete Tenant A site', async () => {
      await request(app.getHttpServer())
        .delete(`/api/v1/sites/${siteIdA}`)
        .set('Authorization', `Bearer ${ownerTokenB}`)
        .expect(404);
    });
  });

  describe('Role-Based Access Control (RBAC) Enforcement', () => {
    let siteIdA: string;

    beforeAll(async () => {
      const listA = await request(app.getHttpServer())
        .get('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`);
      siteIdA = listA.body[0].id;
    });

    it('Viewer and Analyst can READ sites and policies (200 OK)', async () => {
      await request(app.getHttpServer())
        .get('/api/v1/sites')
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .expect(200);

      await request(app.getHttpServer())
        .get(`/api/v1/sites/${siteIdA}/policy`)
        .set('Authorization', `Bearer ${analystTokenA}`)
        .expect(200);
    });

    it('Viewer cannot create site (403 Forbidden)', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/sites')
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .send({
          name: 'Viewer Site',
          domain: 'viewer.tenant-a.com',
          originUrl: 'https://backend.local',
        })
        .expect(403);
    });

    it('Analyst cannot create site (403 Forbidden)', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/sites')
        .set('Authorization', `Bearer ${analystTokenA}`)
        .send({
          name: 'Analyst Site',
          domain: 'analyst.tenant-a.com',
          originUrl: 'https://backend.local',
        })
        .expect(403);
    });

    it('Viewer cannot update site or policy (403 Forbidden)', async () => {
      await request(app.getHttpServer())
        .patch(`/api/v1/sites/${siteIdA}`)
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .send({ name: 'Viewer Renamed' })
        .expect(403);

      await request(app.getHttpServer())
        .put(`/api/v1/sites/${siteIdA}/policy`)
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .send({ mode: WafMode.STRICT })
        .expect(403);
    });

    it('Analyst cannot update policy or trigger rollback (403 Forbidden)', async () => {
      await request(app.getHttpServer())
        .put(`/api/v1/sites/${siteIdA}/policy`)
        .set('Authorization', `Bearer ${analystTokenA}`)
        .send({ mode: WafMode.STRICT })
        .expect(403);

      await request(app.getHttpServer())
        .post(`/api/v1/sites/${siteIdA}/policy/rollback/1`)
        .set('Authorization', `Bearer ${analystTokenA}`)
        .expect(403);
    });

    it('Viewer and Analyst cannot delete site (403 Forbidden)', async () => {
      await request(app.getHttpServer())
        .delete(`/api/v1/sites/${siteIdA}`)
        .set('Authorization', `Bearer ${viewerTokenA}`)
        .expect(403);

      await request(app.getHttpServer())
        .delete(`/api/v1/sites/${siteIdA}`)
        .set('Authorization', `Bearer ${analystTokenA}`)
        .expect(403);
    });
  });

  describe('Site Deletion Lifecycle', () => {
    it('Owner can successfully delete site', async () => {
      const listA = await request(app.getHttpServer())
        .get('/api/v1/sites')
        .set('Authorization', `Bearer ${ownerTokenA}`);
      const siteIdA = listA.body[0].id;

      await request(app.getHttpServer())
        .delete(`/api/v1/sites/${siteIdA}`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(200);

      // Verify site is gone
      await request(app.getHttpServer())
        .get(`/api/v1/sites/${siteIdA}`)
        .set('Authorization', `Bearer ${ownerTokenA}`)
        .expect(404);

      // Verify Audit Log recorded
      const logs = await auditRepo.findByTenant(tenantIdA);
      const deleteLog = logs.find((l) => l.action === 'SITE_DELETED');
      expect(deleteLog).toBeDefined();
      expect(deleteLog?.resourceId).toBe(siteIdA);
    });
  });
});
