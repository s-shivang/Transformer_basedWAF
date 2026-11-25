import { Tenant } from './tenant.entity';
import { TenantId } from './tenant-id.vo';
import { TenantSlug } from './tenant-slug.vo';

export const TENANT_REPOSITORY = Symbol('ITenantRepository');

export interface ITenantRepository {
  findById(id: TenantId): Promise<Tenant | null>;
  findBySlug(slug: TenantSlug): Promise<Tenant | null>;
  findAll(): Promise<Tenant[]>;
  save(tenant: Tenant): Promise<void>;
  delete(id: TenantId): Promise<void>;
  exists(slug: TenantSlug): Promise<boolean>;
}
