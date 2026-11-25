import { TenantTier, TenantStatus } from '../../domain/tenant.entity';
import { ApiProperty } from '@nestjs/swagger';
import { IsNumber, Min, Max } from 'class-validator';

export interface CreateTenantDto {
  name: string;
  slug: string;
  tier?: TenantTier;
  maxSites?: number;
}

export interface TenantResponseDto {
  id: string;
  name: string;
  slug: string;
  tier: TenantTier;
  status: TenantStatus;
  maxSites: number;
  createdAt: string;
  updatedAt: string;
}

export class UpdateTenantQuotaDto {
  @ApiProperty({ example: 10, minimum: 1, maximum: 100 })
  @IsNumber()
  @Min(1)
  @Max(100)
  maxSites: number;
}
