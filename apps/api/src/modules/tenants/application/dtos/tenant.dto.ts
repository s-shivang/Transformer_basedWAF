import { TenantTier, TenantStatus } from '../../domain/tenant.entity';

export interface CreateTenantDto {
  name: string;
  slug: string;
  tier?: TenantTier;
}

export interface TenantResponseDto {
  id: string;
  name: string;
  slug: string;
  tier: TenantTier;
  status: TenantStatus;
  createdAt: string;
  updatedAt: string;
}
