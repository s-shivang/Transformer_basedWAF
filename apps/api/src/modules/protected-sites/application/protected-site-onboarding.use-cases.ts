import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { ProtectedSite, OnboardingStatus, SiteStatus } from '../domain/protected-site.entity';
import { SiteDomain } from '../domain/site-domain.vo';
import { OriginUrl } from '../domain/origin-url.vo';
import {
  IProtectedSiteRepository,
  PROTECTED_SITE_REPOSITORY,
} from '../domain/protected-site.repository.interface';
import {
  ITenantRepository,
  TENANT_REPOSITORY,
} from '../../tenants/domain/tenant.repository.interface';
import { TenantId } from '../../tenants/domain/tenant-id.vo';
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
import {
  IDnsVerifier,
  DNS_VERIFIER,
} from '../domain/dns-verifier.interface';
import {
  ISiteConfigSyncClient,
  SITE_CONFIG_SYNC_CLIENT,
  GatewaySiteSyncPayload,
} from '../domain/site-config-sync.interface';
import {
  StartSiteOnboardingDto,
  RetryOnboardingDto,
  ConfigureSiteDto,
  OnboardingInstructionsResponseDto,
} from '../presentation/dtos/protected-site.dto';

export function toInstructionResponse(site: ProtectedSite): OnboardingInstructionsResponseDto {
  return {
    siteId: site.id,
    name: site.name,
    domain: site.domain.value,
    originUrl: site.originUrl.value,
    onboardingStatus: site.onboardingStatus,
    verificationToken: site.verificationToken,
    configVersion: site.configVersion,
    gatewayAckVersion: site.gatewayAckVersion,
    lastSyncedAt: site.lastSyncedAt ? site.lastSyncedAt.toISOString() : null,
    txtRecord: {
      host: `_waf-challenge.${site.domain.value}`,
      value: site.verificationToken,
      ttl: 300,
    },
    trafficRecord: {
      type: 'CNAME',
      host: site.domain.value,
      target: 'edge.waf-network.internal',
    },
    lastError: site.lastOnboardingError,
    verifiedAt: site.verifiedAt ? site.verifiedAt.toISOString() : null,
  };
}

@Injectable()
export class StartSiteOnboardingUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(TENANT_REPOSITORY) private readonly tenantRepo: ITenantRepository,
    @Inject(WAF_POLICY_REPOSITORY) private readonly policyRepo: IWafPolicyRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(
    tenantId: string,
    dto: StartSiteOnboardingDto,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<OnboardingInstructionsResponseDto>> {
    const domainRes = SiteDomain.create(dto.domain);
    if (domainRes.isFailure) return Result.fail(domainRes.getError());

    const originRes = OriginUrl.create(dto.originUrl);
    if (originRes.isFailure) return Result.fail(originRes.getError());

    const domain = domainRes.getValue();
    const origin = originRes.getValue();

    // 1. Global domain uniqueness check
    const existingGlobal = await this.siteRepo.findGlobalByDomain(domain);
    if (existingGlobal) {
      return Result.fail(`Domain '${domain.value}' is already claimed across the network`);
    }

    // 2. Tenant site quota check
    const currentCount = await this.siteRepo.countByTenant(tenantId);
    const tenantIdVo = TenantId.create(tenantId);
    let maxSites = 5;
    if (tenantIdVo.isSuccess) {
      const tenant = await this.tenantRepo.findById(tenantIdVo.getValue());
      if (tenant) {
        maxSites = tenant.maxSites;
      }
    }

    if (currentCount >= maxSites) {
      return Result.fail(`Tenant site quota limit reached (${maxSites} max protected sites)`);
    }

    // 3. Create site in PENDING_VERIFICATION state
    const site = ProtectedSite.create({
      tenantId,
      name: dto.name,
      domain,
      originUrl: origin,
      onboardingStatus: OnboardingStatus.PENDING_VERIFICATION,
    }).getValue();

    await this.siteRepo.save(site);

    // 4. Default policy
    const defaultPolicy = WafPolicy.createDefault(tenantId, site.id, userId);
    await this.policyRepo.save(defaultPolicy);

    // 5. Audit Log
    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'SITE_ONBOARDING_STARTED',
      resource: 'ProtectedSite',
      resourceId: site.id,
      metadata: {
        domain: domain.value,
        token: site.verificationToken,
        onboardingStatus: site.onboardingStatus,
      },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok(toInstructionResponse(site));
  }
}

@Injectable()
export class GetOnboardingInstructionsUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
  ) {}

  async execute(
    tenantId: string,
    siteId: string,
  ): Promise<Result<OnboardingInstructionsResponseDto>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    return Result.ok(toInstructionResponse(site));
  }
}

@Injectable()
export class VerifySiteDomainUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(DNS_VERIFIER) private readonly dnsVerifier: IDnsVerifier,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(
    tenantId: string,
    siteId: string,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<{ verified: boolean; site: OnboardingInstructionsResponseDto }>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    if (
      site.onboardingStatus === OnboardingStatus.ACTIVE ||
      site.onboardingStatus === OnboardingStatus.VERIFIED
    ) {
      return Result.ok({
        verified: true,
        site: toInstructionResponse(site),
      });
    }

    if (!site.verificationToken) {
      return Result.fail('Site has no verification token assigned');
    }

    const dnsResult = await this.dnsVerifier.verifyTxtRecord(
      site.domain.value,
      site.verificationToken,
    );

    if (dnsResult.verified) {
      const transRes = site.verifyDomain();
      if (transRes.isFailure) {
        return Result.fail(transRes.getError());
      }
      await this.siteRepo.save(site);

      const audit = AuditLog.create({
        tenantId,
        userId,
        action: 'SITE_DOMAIN_VERIFIED',
        resource: 'ProtectedSite',
        resourceId: site.id,
        metadata: { domain: site.domain.value, verifiedAt: site.verifiedAt },
        ipAddress: clientIp,
      }).getValue();
      await this.auditRepo.save(audit);

      return Result.ok({
        verified: true,
        site: toInstructionResponse(site),
      });
    } else {
      site.failOnboarding(dnsResult.error || 'DNS TXT verification failed');
      await this.siteRepo.save(site);

      return Result.fail(
        dnsResult.error || `Verification record '${site.verificationToken}' not found at _waf-challenge.${site.domain.value}`,
      );
    }
  }
}

@Injectable()
export class ConfigureSiteOnGatewayUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(WAF_POLICY_REPOSITORY) private readonly policyRepo: IWafPolicyRepository,
    @Inject(SITE_CONFIG_SYNC_CLIENT) private readonly syncClient: ISiteConfigSyncClient,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(
    tenantId: string,
    siteId: string,
    dto?: ConfigureSiteDto,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<OnboardingInstructionsResponseDto>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    if (
      site.onboardingStatus !== OnboardingStatus.VERIFIED &&
      site.onboardingStatus !== OnboardingStatus.ACTIVE &&
      site.onboardingStatus !== OnboardingStatus.CONFIGURING &&
      site.onboardingStatus !== OnboardingStatus.DNS_PENDING
    ) {
      return Result.fail(
        `Site must be VERIFIED before configuring gateway (current: ${site.onboardingStatus})`,
      );
    }

    // Advance to CONFIGURING
    if (site.onboardingStatus !== OnboardingStatus.CONFIGURING) {
      const transRes = site.transitionTo(OnboardingStatus.CONFIGURING);
      if (transRes.isFailure) {
        return Result.fail(transRes.getError());
      }
      await this.siteRepo.save(site);
    }

    // Resolve active WAF policy
    const policy = await this.policyRepo.findActiveBySite(tenantId, site.id);
    const policyPayload = policy
      ? {
          mode: policy.mode.toLowerCase(),
          block_threshold: policy.thresholds.blockThreshold,
          challenge_threshold: policy.thresholds.challengeThreshold,
          monitor_threshold: policy.thresholds.monitorThreshold,
          ml_enabled: policy.mlEnabled,
          rules_enabled: policy.rulesEnabled,
          challenge_enabled: policy.challengeEnabled,
          exclusions: (policy.exclusions as any[]) || [],
        }
      : {
          mode: 'monitor',
          block_threshold: 0.85,
          challenge_threshold: 0.50,
          monitor_threshold: 0.20,
          ml_enabled: true,
          rules_enabled: true,
          challenge_enabled: true,
          exclusions: [],
        };

    const syncPayload: GatewaySiteSyncPayload = {
      site_id: site.id,
      tenant_id: site.tenantId,
      domain: site.domain.value,
      origin_url: site.originUrl.value,
      enabled: site.status === SiteStatus.ACTIVE,
      config_version: site.configVersion,
      policy: policyPayload,
      force_rollback: Boolean(dto?.forceRollback),
    };

    const syncResult = await this.syncClient.syncSiteConfig(syncPayload);

    if (syncResult.acknowledged) {
      site.acknowledgeGatewaySync(syncResult.config_version);
      await this.siteRepo.save(site);

      const audit = AuditLog.create({
        tenantId,
        userId,
        action: 'SITE_CONFIG_SYNCED',
        resource: 'ProtectedSite',
        resourceId: site.id,
        metadata: {
          domain: site.domain.value,
          configVersion: site.configVersion,
          gatewayAckVersion: site.gatewayAckVersion,
        },
        ipAddress: clientIp,
      }).getValue();
      await this.auditRepo.save(audit);

      return Result.ok(toInstructionResponse(site));
    } else {
      const errorMsg = syncResult.error || 'Gateway configuration sync failed';
      site.failOnboarding(errorMsg);
      await this.siteRepo.save(site);

      const audit = AuditLog.create({
        tenantId,
        userId,
        action: 'SITE_CONFIG_SYNC_FAILED',
        resource: 'ProtectedSite',
        resourceId: site.id,
        metadata: {
          domain: site.domain.value,
          configVersion: site.configVersion,
          error: errorMsg,
        },
        ipAddress: clientIp,
      }).getValue();
      await this.auditRepo.save(audit);

      return Result.fail(errorMsg);
    }
  }
}

@Injectable()
export class RetrySiteOnboardingUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(
    tenantId: string,
    siteId: string,
    dto?: RetryOnboardingDto,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<OnboardingInstructionsResponseDto>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    const target = dto?.targetStatus ?? OnboardingStatus.PENDING_VERIFICATION;
    const retryRes = site.retryOnboarding(target);
    if (retryRes.isFailure) {
      return Result.fail(retryRes.getError());
    }

    await this.siteRepo.save(site);

    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'SITE_ONBOARDING_RETRIED',
      resource: 'ProtectedSite',
      resourceId: site.id,
      metadata: { targetStatus: target },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok(toInstructionResponse(site));
  }
}

@Injectable()
export class PauseResumeSiteUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(SITE_CONFIG_SYNC_CLIENT) private readonly syncClient: ISiteConfigSyncClient,
    @Inject(WAF_POLICY_REPOSITORY) private readonly policyRepo: IWafPolicyRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async pause(
    tenantId: string,
    siteId: string,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<OnboardingInstructionsResponseDto>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    const pauseRes = site.pause();
    if (pauseRes.isFailure) {
      return Result.fail(pauseRes.getError());
    }

    await this.siteRepo.save(site);

    // Evict from Gateway HostRegistry
    try {
      await this.syncClient.removeSiteConfig(site.domain.value);
    } catch {
      // Non-blocking
    }

    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'SITE_PAUSED',
      resource: 'ProtectedSite',
      resourceId: site.id,
      metadata: { status: site.status },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok(toInstructionResponse(site));
  }

  async resume(
    tenantId: string,
    siteId: string,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<OnboardingInstructionsResponseDto>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    const resumeRes = site.resume();
    if (resumeRes.isFailure) {
      return Result.fail(resumeRes.getError());
    }

    await this.siteRepo.save(site);

    // Re-sync route config to Gateway
    try {
      const policy = await this.policyRepo.findActiveBySite(tenantId, site.id);
      await this.syncClient.syncSiteConfig({
        site_id: site.id,
        tenant_id: site.tenantId,
        domain: site.domain.value,
        origin_url: site.originUrl.value,
        enabled: true,
        config_version: site.configVersion,
        policy: policy ? {
          mode: policy.mode.toLowerCase(),
          block_threshold: policy.thresholds.blockThreshold,
          challenge_threshold: policy.thresholds.challengeThreshold,
          monitor_threshold: policy.thresholds.monitorThreshold,
          ml_enabled: policy.mlEnabled,
          rules_enabled: policy.rulesEnabled,
          challenge_enabled: policy.challengeEnabled,
          exclusions: (policy.exclusions as any[]) || [],
        } : undefined,
      });
    } catch {
      // Non-blocking resume sync attempt
    }

    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'SITE_RESUMED',
      resource: 'ProtectedSite',
      resourceId: site.id,
      metadata: { status: site.status },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok(toInstructionResponse(site));
  }
}
