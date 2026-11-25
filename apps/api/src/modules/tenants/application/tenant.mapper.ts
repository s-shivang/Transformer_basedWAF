import { Tenant } from '../domain/tenant.entity';
import { TenantResponseDto } from './dtos/tenant.dto';

export class TenantMapper {
  public static toResponseDto(tenant: Tenant): TenantResponseDto {
    return {
      id: tenant.id.value,
      name: tenant.name,
      slug: tenant.slug.value,
      tier: tenant.tier,
      status: tenant.status,
      createdAt: tenant.createdAt.toISOString(),
      updatedAt: tenant.updatedAt.toISOString(),
    };
  }
}
