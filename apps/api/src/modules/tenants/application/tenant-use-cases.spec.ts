import { CreateTenantUseCase } from './create-tenant.use-case';
import { GetTenantByIdUseCase } from './get-tenant-by-id.use-case';
import { GetTenantBySlugUseCase } from './get-tenant-by-slug.use-case';
import { ListTenantsUseCase } from './list-tenants.use-case';
import { InMemoryTenantRepository } from '../infrastructure/in-memory-tenant.repository';
import { TenantTier, TenantStatus } from '../domain/tenant.entity';

describe('Tenant Application Use Cases', () => {
  let repository: InMemoryTenantRepository;
  let createUseCase: CreateTenantUseCase;
  let getByIdUseCase: GetTenantByIdUseCase;
  let getBySlugUseCase: GetTenantBySlugUseCase;
  let listUseCase: ListTenantsUseCase;

  beforeEach(() => {
    repository = new InMemoryTenantRepository();
    createUseCase = new CreateTenantUseCase(repository);
    getByIdUseCase = new GetTenantByIdUseCase(repository);
    getBySlugUseCase = new GetTenantBySlugUseCase(repository);
    listUseCase = new ListTenantsUseCase(repository);
  });

  it('should successfully create a tenant and persist it', async () => {
    const res = await createUseCase.execute({
      name: 'Stark Industries',
      slug: 'stark-industries',
      tier: TenantTier.ENTERPRISE,
    });

    expect(res.isSuccess).toBe(true);
    const dto = res.getValue();
    expect(dto.name).toBe('Stark Industries');
    expect(dto.slug).toBe('stark-industries');
    expect(dto.tier).toBe(TenantTier.ENTERPRISE);
    expect(dto.status).toBe(TenantStatus.ACTIVE);

    // Retrieve via list
    const listRes = await listUseCase.execute();
    expect(listRes.getValue().length).toBe(1);
    expect(listRes.getValue()[0].id).toBe(dto.id);
  });

  it('should reject duplicate tenant slugs', async () => {
    await createUseCase.execute({
      name: 'Stark Industries',
      slug: 'stark-industries',
    });

    const duplicateRes = await createUseCase.execute({
      name: 'Stark Clone',
      slug: 'stark-industries',
    });

    expect(duplicateRes.isFailure).toBe(true);
    expect(duplicateRes.getError()).toContain('already exists');
  });

  it('should fetch tenant by ID and slug', async () => {
    const created = (
      await createUseCase.execute({
        name: 'Wayne Enterprises',
        slug: 'wayne-enterprises',
      })
    ).getValue();

    const byId = await getByIdUseCase.execute(created.id);
    expect(byId.isSuccess).toBe(true);
    expect(byId.getValue().slug).toBe('wayne-enterprises');

    const bySlug = await getBySlugUseCase.execute('wayne-enterprises');
    expect(bySlug.isSuccess).toBe(true);
    expect(bySlug.getValue().id).toBe(created.id);
  });

  it('should return error when tenant not found', async () => {
    const notFoundId = await getByIdUseCase.execute('non-existent-id');
    expect(notFoundId.isFailure).toBe(true);
    expect(notFoundId.getError()).toContain('not found');

    const notFoundSlug = await getBySlugUseCase.execute('unknown-slug');
    expect(notFoundSlug.isFailure).toBe(true);
    expect(notFoundSlug.getError()).toContain('not found');
  });
});
