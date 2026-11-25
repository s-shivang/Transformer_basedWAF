import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as cookieParser from 'cookie-parser';
import { AppModule } from '../src/app.module';
import { TENANT_REPOSITORY } from '../src/modules/tenants/domain/tenant.repository.interface';
import { InMemoryTenantRepository } from '../src/modules/tenants/infrastructure/in-memory-tenant.repository';
import { TOKEN_SERVICE, ITokenService } from '../src/modules/identity/infrastructure/token.service';

describe('Tenants API (E2E Integration)', () => {
  let app: INestApplication;
  let inMemoryRepo: InMemoryTenantRepository;
  let tokenService: ITokenService;
  let validToken: string;

  beforeAll(async () => {
    inMemoryRepo = new InMemoryTenantRepository();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(TENANT_REPOSITORY)
      .useValue(inMemoryRepo)
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

    tokenService = app.get(TOKEN_SERVICE);
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    inMemoryRepo.clear();
  });

  it('GET /api/v1/health should return ok', () => {
    return request(app.getHttpServer())
      .get('/api/v1/health')
      .expect(200)
      .expect((res) => {
        expect(res.body.status).toBe('ok');
        expect(res.body.service).toBe('transformer-waf-saas-api');
      });
  });

  it('POST /api/v1/tenants should create a new tenant', () => {
    return request(app.getHttpServer())
      .post('/api/v1/tenants')
      .send({
        name: 'Cyberdyne Systems',
        slug: 'cyberdyne-sys',
        tier: 'PRO',
      })
      .expect(201)
      .expect((res) => {
        expect(res.body.id).toBeDefined();
        expect(res.body.name).toBe('Cyberdyne Systems');
        expect(res.body.slug).toBe('cyberdyne-sys');
        expect(res.body.tier).toBe('PRO');
      });
  });

  it('POST /api/v1/tenants should reject invalid slug format', () => {
    return request(app.getHttpServer())
      .post('/api/v1/tenants')
      .send({
        name: 'Invalid Slug Org',
        slug: 'INVALID_SLUG!',
      })
      .expect(400);
  });

  it('GET /api/v1/tenants should return caller active tenant when authenticated', async () => {
    const createRes = await request(app.getHttpServer())
      .post('/api/v1/tenants')
      .send({ name: 'Org One', slug: 'org-one' })
      .expect(201);

    const callerToken = tokenService.generateAccessToken({
      sub: 'caller-user-id',
      tenantId: createRes.body.id,
      role: 'OWNER',
      email: 'owner@orgone.com',
    });

    const res = await request(app.getHttpServer())
      .get('/api/v1/tenants')
      .set('Authorization', `Bearer ${callerToken}`)
      .expect(200);

    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBe(1);
    expect(res.body[0].id).toBe(createRes.body.id);
  });

  it('GET /api/v1/tenants/slug/:slug should retrieve tenant by slug for authenticated member', async () => {
    const createRes = await request(app.getHttpServer())
      .post('/api/v1/tenants')
      .send({ name: 'Lookup Tenant', slug: 'lookup-tenant' })
      .expect(201);

    const callerToken = tokenService.generateAccessToken({
      sub: 'caller-user-id',
      tenantId: createRes.body.id,
      role: 'ADMIN',
      email: 'admin@lookuptenant.com',
    });

    const res = await request(app.getHttpServer())
      .get('/api/v1/tenants/slug/lookup-tenant')
      .set('Authorization', `Bearer ${callerToken}`)
      .expect(200);

    expect(res.body.slug).toBe('lookup-tenant');
    expect(res.body.name).toBe('Lookup Tenant');
  });

  it('GET /api/v1/tenants/slug/non-existent should return 404', () => {
    const callerToken = tokenService.generateAccessToken({
      sub: 'caller-user-id',
      tenantId: 'some-tenant-id',
      role: 'VIEWER',
      email: 'viewer@example.com',
    });

    return request(app.getHttpServer())
      .get('/api/v1/tenants/slug/non-existent')
      .set('Authorization', `Bearer ${callerToken}`)
      .expect(404);
  });
});
