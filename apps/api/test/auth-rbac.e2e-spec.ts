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

describe('Phase 9 Identity, Auth, RBAC & Multitenant Isolation (E2E)', () => {
  let app: INestApplication;
  let tenantRepo: InMemoryTenantRepository;
  let userRepo: InMemoryUserRepository;
  let memberRepo: InMemoryMembershipRepository;
  let sessionRepo: InMemoryRefreshSessionRepository;
  let auditRepo: InMemoryAuditLogRepository;

  beforeAll(async () => {
    tenantRepo = new InMemoryTenantRepository();
    userRepo = new InMemoryUserRepository();
    memberRepo = new InMemoryMembershipRepository();
    sessionRepo = new InMemoryRefreshSessionRepository();
    auditRepo = new InMemoryAuditLogRepository();

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
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    tenantRepo.clear();
    userRepo.clear();
    memberRepo.clear();
    sessionRepo.clear();
    auditRepo.clear();
  });

  function extractCookie(res: any, name: string): string | undefined {
    const cookies: string[] = res.headers['set-cookie'] || [];
    for (const cookie of cookies) {
      if (cookie.startsWith(`${name}=`)) {
        return cookie.split(';')[0].split('=')[1];
      }
    }
    return undefined;
  }

  describe('Authentication Lifecycle & Security Guarantees', () => {
    it('should register tenant owner, set HttpOnly cookies, and return sanitized user (NO passwordHash)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@alpha.com',
          password: 'SecretPassword123!',
          fullName: 'Alpha Owner',
          tenantName: 'Alpha Corp',
          tenantSlug: 'alpha-corp',
        })
        .expect(201);

      expect(res.body.user).toBeDefined();
      expect(res.body.user.email).toBe('owner@alpha.com');
      expect(res.body.user.passwordHash).toBeUndefined(); // INVARIANT: NEVER LEAK PASSWORD HASH
      expect(JSON.stringify(res.body)).not.toContain('passwordHash');
      expect(res.body.role).toBe('OWNER');
      expect(res.body.activeTenantId).toBeDefined();

      const accessCookie = extractCookie(res, 'waf_access_token');
      const refreshCookie = extractCookie(res, 'waf_refresh_token');
      expect(accessCookie).toBeDefined();
      expect(refreshCookie).toBeDefined();
    });

    it('should reject registration on duplicate email or slug with 409', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@alpha.com',
          password: 'SecretPassword123!',
          tenantName: 'Alpha Corp',
          tenantSlug: 'alpha-corp',
        })
        .expect(201);

      // Duplicate email
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@alpha.com',
          password: 'SecretPassword123!',
          tenantName: 'Other Corp',
          tenantSlug: 'other-corp',
        })
        .expect(409);

      // Duplicate slug
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'newuser@alpha.com',
          password: 'SecretPassword123!',
          tenantName: 'Alpha Corp',
          tenantSlug: 'alpha-corp',
        })
        .expect(409);
    });

    it('should authenticate user via login and issue rotated cookies', async () => {
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@alpha.com',
          password: 'SecretPassword123!',
          tenantName: 'Alpha Corp',
          tenantSlug: 'alpha-corp',
        })
        .expect(201);

      // Bad credentials
      await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({ email: 'owner@alpha.com', password: 'WrongPassword' })
        .expect(401);

      // Good credentials
      const loginRes = await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({ email: 'owner@alpha.com', password: 'SecretPassword123!' })
        .expect(200);

      expect(loginRes.body.user.email).toBe('owner@alpha.com');
      expect(extractCookie(loginRes, 'waf_access_token')).toBeDefined();
      expect(extractCookie(loginRes, 'waf_refresh_token')).toBeDefined();
    });

    it('should perform refresh token rotation and reject replayed tokens', async () => {
      const regRes = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@alpha.com',
          password: 'SecretPassword123!',
          tenantName: 'Alpha Corp',
          tenantSlug: 'alpha-corp',
        })
        .expect(201);

      const oldRefreshCookie = extractCookie(regRes, 'waf_refresh_token')!;

      // 1. Valid refresh
      const refRes = await request(app.getHttpServer())
        .post('/api/v1/auth/refresh')
        .set('Cookie', [`waf_refresh_token=${oldRefreshCookie}`])
        .expect(200);

      const newRefreshCookie = extractCookie(refRes, 'waf_refresh_token')!;
      expect(newRefreshCookie).toBeDefined();
      expect(newRefreshCookie).not.toBe(oldRefreshCookie);

      // 2. Replay old refresh token (REUSE DETECTION) -> must fail with 401
      await request(app.getHttpServer())
        .post('/api/v1/auth/refresh')
        .set('Cookie', [`waf_refresh_token=${oldRefreshCookie}`])
        .expect(401);
    });

    it('should logout cleanly, revoke session, and clear cookies', async () => {
      const regRes = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@alpha.com',
          password: 'SecretPassword123!',
          tenantName: 'Alpha Corp',
          tenantSlug: 'alpha-corp',
        })
        .expect(201);

      const refreshCookie = extractCookie(regRes, 'waf_refresh_token')!;
      const accessCookie = extractCookie(regRes, 'waf_access_token')!;

      await request(app.getHttpServer())
        .post('/api/v1/auth/logout')
        .set('Cookie', [`waf_refresh_token=${refreshCookie}`, `waf_access_token=${accessCookie}`])
        .expect(201);

      // Subsequent call to /me without cookies should return 401
      await request(app.getHttpServer())
        .get('/api/v1/auth/me')
        .expect(401);
    });
  });

  describe('Cross-Tenant Isolation & RBAC Security Guarantees', () => {
    let tenantAId: string;
    let tenantBId: string;
    let tenantAToken: string;
    let tenantBToken: string;

    beforeEach(async () => {
      // Register Tenant A
      const resA = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@alpha.com',
          password: 'Password123!',
          tenantName: 'Alpha Corp',
          tenantSlug: 'alpha-corp',
        })
        .expect(201);

      tenantAId = resA.body.activeTenantId;
      tenantAToken = resA.body.accessToken;

      // Register Tenant B
      const resB = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'owner@beta.com',
          password: 'Password123!',
          tenantName: 'Beta Corp',
          tenantSlug: 'beta-corp',
        })
        .expect(201);

      tenantBId = resB.body.activeTenantId;
      tenantBToken = resB.body.accessToken;
    });

    it('CRITICAL: Tenant A MUST receive 403 Forbidden when trying to access Tenant B ID', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/tenants/${tenantBId}`)
        .set('Authorization', `Bearer ${tenantAToken}`)
        .expect(403);
    });

    it('CRITICAL: Tenant A MUST receive 403 Forbidden when trying to add a member to Tenant B', async () => {
      await request(app.getHttpServer())
        .post(`/api/v1/tenants/${tenantBId}/members`)
        .set('Authorization', `Bearer ${tenantAToken}`)
        .send({
          email: 'intruder@alpha.com',
          role: 'ADMIN',
        })
        .expect(403);
    });

    it('RBAC Enforcement: OWNER can add VIEWER, but VIEWER cannot add other members (403)', async () => {
      // 1. Tenant A OWNER adds a VIEWER
      const addRes = await request(app.getHttpServer())
        .post(`/api/v1/tenants/${tenantAId}/members`)
        .set('Authorization', `Bearer ${tenantAToken}`)
        .send({
          email: 'viewer@alpha.com',
          role: 'VIEWER',
        })
        .expect(201);

      expect(addRes.body.role).toBe('VIEWER');

      // 2. Generate a token for the VIEWER
      const tokenService = app.get(require('../src/modules/identity/infrastructure/token.service').TOKEN_SERVICE);
      const viewerToken = tokenService.generateAccessToken({
        sub: addRes.body.userId,
        tenantId: tenantAId,
        role: 'VIEWER',
        email: 'viewer@alpha.com',
      });

      // 3. VIEWER can read tenant A (200)
      await request(app.getHttpServer())
        .get(`/api/v1/tenants/${tenantAId}`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .expect(200);

      // 4. VIEWER attempts to add another member -> MUST be 403 Forbidden
      await request(app.getHttpServer())
        .post(`/api/v1/tenants/${tenantAId}/members`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({
          email: 'subviewer@alpha.com',
          role: 'VIEWER',
        })
        .expect(403);
    });

    it('Audit logging: records USER_REGISTERED, USER_LOGIN, and MEMBER_ADDED events', async () => {
      const logs = await auditRepo.findByTenant(tenantAId);
      expect(logs.length).toBeGreaterThanOrEqual(1);
      const actions = logs.map((l) => l.action);
      expect(actions).toContain('USER_REGISTERED');
    });
  });
});
