import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';
import { TENANT_REPOSITORY } from '../../src/modules/tenants/domain/tenant.repository.interface';
import { InMemoryTenantRepository } from '../../src/modules/tenants/infrastructure/in-memory-tenant.repository';

describe('Tenants API (E2E Integration)', () => {
  let app: INestApplication;
  let inMemoryRepo: InMemoryTenantRepository;

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

  it('GET /api/v1/tenants should list all created tenants', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/tenants')
      .send({ name: 'Org One', slug: 'org-one' })
      .expect(201);

    await request(app.getHttpServer())
      .post('/api/v1/tenants')
      .send({ name: 'Org Two', slug: 'org-two' })
      .expect(201);

    const res = await request(app.getHttpServer())
      .get('/api/v1/tenants')
      .expect(200);

    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBe(2);
  });

  it('GET /api/v1/tenants/slug/:slug should retrieve tenant by slug', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/tenants')
      .send({ name: 'Lookup Tenant', slug: 'lookup-tenant' })
      .expect(201);

    const res = await request(app.getHttpServer())
      .get('/api/v1/tenants/slug/lookup-tenant')
      .expect(200);

    expect(res.body.slug).toBe('lookup-tenant');
    expect(res.body.name).toBe('Lookup Tenant');
  });

  it('GET /api/v1/tenants/slug/non-existent should return 404', () => {
    return request(app.getHttpServer())
      .get('/api/v1/tenants/slug/non-existent')
      .expect(404);
  });
});
