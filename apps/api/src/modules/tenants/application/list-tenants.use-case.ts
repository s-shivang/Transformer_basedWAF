import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import {
  ITenantRepository,
  TENANT_REPOSITORY,
} from '../domain/tenant.repository.interface';
import { TenantResponseDto } from './dtos/tenant.dto';
import { TenantMapper } from './tenant.mapper';

@Injectable()
export class ListTenantsUseCase {
  constructor(
    @Inject(TENANT_REPOSITORY)
    private readonly tenantRepository: ITenantRepository,
  ) {}

  async execute(): Promise<Result<TenantResponseDto[]>> {
    const tenants = await this.tenantRepository.findAll();
    const dtos = tenants.map((t) => TenantMapper.toResponseDto(t));
    return Result.ok<TenantResponseDto[]>(dtos);
  }
}
