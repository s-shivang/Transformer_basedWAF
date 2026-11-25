import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { ITenantRepository, TENANT_REPOSITORY } from '../domain/tenant.repository.interface';
import { TenantId } from '../domain/tenant-id.vo';
import { TenantResponseDto, UpdateTenantQuotaDto } from './dtos/tenant.dto';
import { TenantMapper } from './tenant.mapper';
import {
  IAuditLogRepository,
  AUDIT_LOG_REPOSITORY,
} from '../../identity/domain/identity.repository.interfaces';
import { AuditLog } from '../../identity/domain/audit-log.entity';

@Injectable()
export class UpdateTenantQuotaUseCase {
  constructor(
    @Inject(TENANT_REPOSITORY) private readonly tenantRepo: ITenantRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(
    tenantId: string,
    dto: UpdateTenantQuotaDto,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<TenantResponseDto>> {
    const idRes = TenantId.create(tenantId);
    if (idRes.isFailure) {
      return Result.fail(idRes.getError());
    }

    const tenant = await this.tenantRepo.findById(idRes.getValue());
    if (!tenant) {
      return Result.fail(`Tenant '${tenantId}' not found`);
    }

    const prevQuota = tenant.maxSites;
    const updateRes = tenant.updateSiteQuota(dto.maxSites);
    if (updateRes.isFailure) {
      return Result.fail(updateRes.getError());
    }

    await this.tenantRepo.save(tenant);

    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'TENANT_QUOTA_UPDATED',
      resource: 'Tenant',
      resourceId: tenant.id.value,
      metadata: { previousMaxSites: prevQuota, newMaxSites: tenant.maxSites },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok(TenantMapper.toResponseDto(tenant));
  }
}
