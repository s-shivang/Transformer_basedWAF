import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { Tenant, TenantTier } from '../domain/tenant.entity';
import { TenantSlug } from '../domain/tenant-slug.vo';
import {
  ITenantRepository,
  TENANT_REPOSITORY,
} from '../domain/tenant.repository.interface';
import { CreateTenantDto, TenantResponseDto } from './dtos/tenant.dto';
import { TenantMapper } from './tenant.mapper';

@Injectable()
export class CreateTenantUseCase {
  constructor(
    @Inject(TENANT_REPOSITORY)
    private readonly tenantRepository: ITenantRepository,
  ) {}

  async execute(dto: CreateTenantDto): Promise<Result<TenantResponseDto>> {
    const slugResult = TenantSlug.create(dto.slug);
    if (slugResult.isFailure) {
      return Result.fail<TenantResponseDto>(slugResult.getError());
    }

    const slug = slugResult.getValue();
    const slugExists = await this.tenantRepository.exists(slug);
    if (slugExists) {
      return Result.fail<TenantResponseDto>(
        `Tenant with slug '${slug.value}' already exists`,
      );
    }

    const tenantResult = Tenant.create({
      name: dto.name,
      slug: slug,
      tier: dto.tier ?? TenantTier.FREE,
    });

    if (tenantResult.isFailure) {
      return Result.fail<TenantResponseDto>(tenantResult.getError());
    }

    const tenant = tenantResult.getValue();
    await this.tenantRepository.save(tenant);

    return Result.ok<TenantResponseDto>(TenantMapper.toResponseDto(tenant));
  }
}
