import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { ProtectedSite, SiteStatus } from '../domain/protected-site.entity';
import { SiteDomain } from '../domain/site-domain.vo';
import { OriginUrl } from '../domain/origin-url.vo';
import {
  IProtectedSiteRepository,
  PROTECTED_SITE_REPOSITORY,
} from '../domain/protected-site.repository.interface';
import {
  IWafPolicyRepository,
  WAF_POLICY_REPOSITORY,
} from '../../waf-policies/domain/waf-policy.repository.interface';
import { WafPolicy } from '../../waf-policies/domain/waf-policy.entity';
import {
  IAuditLogRepository,
  AUDIT_LOG_REPOSITORY,
} from '../../identity/domain/identity.repository.interfaces';
import { AuditLog } from '../../identity/domain/audit-log.entity';
import { CreateProtectedSiteDto, UpdateProtectedSiteDto } from '../presentation/dtos/protected-site.dto';

@Injectable()
export class CreateProtectedSiteUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(WAF_POLICY_REPOSITORY) private readonly policyRepo: IWafPolicyRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(tenantId: string, dto: CreateProtectedSiteDto, userId?: string, clientIp?: string): Promise<Result<any>> {
    const domainRes = SiteDomain.create(dto.domain);
    if (domainRes.isFailure) return Result.fail(domainRes.getError());

    const originRes = OriginUrl.create(dto.originUrl);
    if (originRes.isFailure) return Result.fail(originRes.getError());

    const domain = domainRes.getValue();
    const origin = originRes.getValue();

    const exists = await this.siteRepo.exists(tenantId, domain);
    if (exists) {
      return Result.fail(`Site with domain '${domain.value}' already exists for this tenant`);
    }

    const site = ProtectedSite.create({
      tenantId,
      name: dto.name,
      domain,
      originUrl: origin,
    }).getValue();

    await this.siteRepo.save(site);

    // Automatically provision safe default v1 MONITOR WafPolicy
    const defaultPolicy = WafPolicy.createDefault(tenantId, site.id, userId);
    await this.policyRepo.save(defaultPolicy);

    // Audit Log
    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'SITE_CREATED',
      resource: 'ProtectedSite',
      resourceId: site.id,
      metadata: { domain: domain.value, originUrl: origin.value, initialPolicyId: defaultPolicy.id },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok({
      id: site.id,
      tenantId: site.tenantId,
      name: site.name,
      domain: site.domain.value,
      originUrl: site.originUrl.value,
      status: site.status,
      createdAt: site.createdAt.toISOString(),
      updatedAt: site.updatedAt.toISOString(),
      defaultPolicyVersion: defaultPolicy.version,
    });
  }
}

@Injectable()
export class ListProtectedSitesUseCase {
  constructor(@Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository) {}

  async execute(tenantId: string): Promise<Result<any[]>> {
    const sites = await this.siteRepo.findAllByTenant(tenantId);
    return Result.ok(
      sites.map((s) => ({
        id: s.id,
        tenantId: s.tenantId,
        name: s.name,
        domain: s.domain.value,
        originUrl: s.originUrl.value,
        status: s.status,
        createdAt: s.createdAt.toISOString(),
        updatedAt: s.updatedAt.toISOString(),
      })),
    );
  }
}

@Injectable()
export class GetProtectedSiteUseCase {
  constructor(@Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository) {}

  async execute(tenantId: string, siteId: string): Promise<Result<any>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) return Result.fail(`Protected site '${siteId}' not found`);

    return Result.ok({
      id: site.id,
      tenantId: site.tenantId,
      name: site.name,
      domain: site.domain.value,
      originUrl: site.originUrl.value,
      status: site.status,
      createdAt: site.createdAt.toISOString(),
      updatedAt: site.updatedAt.toISOString(),
    });
  }
}

@Injectable()
export class UpdateProtectedSiteUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(tenantId: string, siteId: string, dto: UpdateProtectedSiteDto, userId?: string, clientIp?: string): Promise<Result<any>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) return Result.fail(`Protected site '${siteId}' not found`);

    let origin: OriginUrl | undefined;
    if (dto.originUrl) {
      const origRes = OriginUrl.create(dto.originUrl);
      if (origRes.isFailure) return Result.fail(origRes.getError());
      origin = origRes.getValue();
    }

    site.update({
      name: dto.name,
      originUrl: origin,
      status: dto.status as SiteStatus,
    });

    await this.siteRepo.save(site);

    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'SITE_UPDATED',
      resource: 'ProtectedSite',
      resourceId: site.id,
      metadata: { updates: dto },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok({
      id: site.id,
      name: site.name,
      domain: site.domain.value,
      originUrl: site.originUrl.value,
      status: site.status,
      updatedAt: site.updatedAt.toISOString(),
    });
  }
}

@Injectable()
export class DeleteProtectedSiteUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(tenantId: string, siteId: string, userId?: string, clientIp?: string): Promise<Result<void>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) return Result.fail(`Protected site '${siteId}' not found`);

    await this.siteRepo.delete(tenantId, siteId);

    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'SITE_DELETED',
      resource: 'ProtectedSite',
      resourceId: siteId,
      metadata: { domain: site.domain.value },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok();
  }
}
