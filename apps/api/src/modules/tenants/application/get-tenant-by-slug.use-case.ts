import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { TenantSlug } from '../domain/tenant-slug.vo';
import {
  ITenantRepository,
  TENANT_REPOSITORY,
} from '../domain/tenant.repository.interface';
import { TenantResponseDto } from './dtos/tenant.dto';
import { TenantMapper } from './tenant.mapper';

@Injectable()
export class GetTenantBySlugUseCase {
  constructor(
    @Inject(TENANT_REPOSITORY)
    private readonly tenantRepository: ITenantRepository,
  ) {}

  async execute(rawSlug: string): Promise<Result<TenantResponseDto>> {
    const slugResult = TenantSlug.create(rawSlug);
    if (slugResult.isFailure) {
      return Result.fail<TenantResponseDto>(slugResult.getError());
    }

    const tenant = await this.tenantRepository.findBySlug(slugResult.getValue());
    if (!tenant) {
      return Result.fail<TenantResponseDto>(
        `Tenant with slug '${rawSlug}' not found`,
      );
    }

    return Result.ok<TenantResponseDto>(TenantMapper.toResponseDto(tenant));
  }
}
