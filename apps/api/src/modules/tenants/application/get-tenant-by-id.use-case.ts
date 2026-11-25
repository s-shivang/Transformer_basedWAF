import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { TenantId } from '../domain/tenant-id.vo';
import {
  ITenantRepository,
  TENANT_REPOSITORY,
} from '../domain/tenant.repository.interface';
import { TenantResponseDto } from './dtos/tenant.dto';
import { TenantMapper } from './tenant.mapper';

@Injectable()
export class GetTenantByIdUseCase {
  constructor(
    @Inject(TENANT_REPOSITORY)
    private readonly tenantRepository: ITenantRepository,
  ) {}

  async execute(idString: string): Promise<Result<TenantResponseDto>> {
    const idResult = TenantId.create(idString);
    if (idResult.isFailure) {
      return Result.fail<TenantResponseDto>(idResult.getError());
    }

    const tenant = await this.tenantRepository.findById(idResult.getValue());
    if (!tenant) {
      return Result.fail<TenantResponseDto>(
        `Tenant with ID '${idString}' not found`,
      );
    }

    return Result.ok<TenantResponseDto>(TenantMapper.toResponseDto(tenant));
  }
}
