import { Tenant } from '../domain/tenant.entity';
import { TenantId } from '../domain/tenant-id.vo';
import { TenantSlug } from '../domain/tenant-slug.vo';
import { ITenantRepository } from '../domain/tenant.repository.interface';

export class InMemoryTenantRepository implements ITenantRepository {
  private tenants: Map<string, Tenant> = new Map();

  async findById(id: TenantId): Promise<Tenant | null> {
    const tenant = this.tenants.get(id.value);
    return tenant ? tenant : null;
  }

  async findBySlug(slug: TenantSlug): Promise<Tenant | null> {
    for (const tenant of this.tenants.values()) {
      if (tenant.slug.value === slug.value) {
        return tenant;
      }
    }
    return null;
  }

  async findAll(): Promise<Tenant[]> {
    return Array.from(this.tenants.values());
  }

  async save(tenant: Tenant): Promise<void> {
    this.tenants.set(tenant.id.value, tenant);
  }

  async delete(id: TenantId): Promise<void> {
    this.tenants.delete(id.value);
  }

  async exists(slug: TenantSlug): Promise<boolean> {
    const found = await this.findBySlug(slug);
    return found !== null;
  }

  public clear(): void {
    this.tenants.clear();
  }
}
