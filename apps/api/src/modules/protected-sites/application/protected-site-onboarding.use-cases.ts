import { Inject, Injectable, Optional } from '@nestjs/common';
import * as crypto from 'crypto';
import { Result } from '@shared/application/result';
import {
  ProtectedSite,
  OnboardingStatus,
  SiteStatus,
  TlsStatus,
  OriginHealthStatus,
} from '../domain/protected-site.entity';
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
  ITlsProvisioner,
  TLS_PROVISIONER,
} from '../domain/tls-provisioner.interface';
import {
  IOriginHealthChecker,
  ORIGIN_HEALTH_CHECKER,
} from '../domain/origin-health-checker.interface';
import {
  NOTIFICATION_REPOSITORY,
  INotificationRepository,
} from '../../notifications/domain/repositories/notification.repository.interface';
import { Notification } from '../../notifications/domain/notification.entity';
import {
  StartSiteOnboardingDto,
  RetryOnboardingDto,
  ConfigureSiteDto,
  OnboardingInstructionsResponseDto,
  SiteHealthCheckResponseDto,
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
    tlsStatus: site.tlsStatus,
    tlsIssuer: site.tlsIssuer,
    tlsExpiresAt: site.tlsExpiresAt ? site.tlsExpiresAt.toISOString() : null,
    originHealthStatus: site.originHealthStatus,
    lastHealthCheckAt: site.lastHealthCheckAt ? site.lastHealthCheckAt.toISOString() : null,
    activatedAt: site.activatedAt ? site.activatedAt.toISOString() : null,
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

@Injectable()
export class VerifyDnsRoutingUseCase {
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
  ): Promise<Result<OnboardingInstructionsResponseDto>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    if (site.onboardingStatus !== OnboardingStatus.DNS_PENDING) {
      return Result.fail(
        `Site must be in DNS_PENDING state to verify DNS routing (current: ${site.onboardingStatus})`,
      );
    }

    const expectedTarget = process.env.WAF_EDGE_TARGET || 'edge.waf-network.internal';
    const trafficResult = await this.dnsVerifier.verifyTrafficRecord(
      site.domain.value,
      expectedTarget,
    );

    if (trafficResult.pointed) {
      const transRes = site.markDnsRoutingVerified();
      if (transRes.isFailure) {
        return Result.fail(transRes.getError());
      }

      await this.siteRepo.save(site);

      const audit = AuditLog.create({
        tenantId,
        userId,
        action: 'SITE_DNS_ROUTING_VERIFIED',
        resource: 'ProtectedSite',
        resourceId: site.id,
        metadata: {
          domain: site.domain.value,
          target: expectedTarget,
          onboardingStatus: site.onboardingStatus,
        },
        ipAddress: clientIp,
      }).getValue();
      await this.auditRepo.save(audit);

      return Result.ok(toInstructionResponse(site));
    } else {
      const errorMsg =
        trafficResult.error ||
        `Domain '${site.domain.value}' does not point to '${expectedTarget}'. Ensure CNAME or A record is created at your DNS provider.`;
      return Result.fail(errorMsg);
    }
  }
}

@Injectable()
export class ProvisionSiteTlsUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(TLS_PROVISIONER) private readonly tlsProvisioner: ITlsProvisioner,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(
    tenantId: string,
    siteId: string,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<OnboardingInstructionsResponseDto>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    if (site.onboardingStatus !== OnboardingStatus.TLS_PENDING) {
      return Result.fail(
        `Site must be in TLS_PENDING state to provision TLS (current: ${site.onboardingStatus})`,
      );
    }

    const provisionResult = await this.tlsProvisioner.provisionCertificate(site.domain.value);

    if (provisionResult.provisioned) {
      const transRes = site.markTlsProvisioned(provisionResult.issuer, provisionResult.expiresAt);
      if (transRes.isFailure) {
        return Result.fail(transRes.getError());
      }
      await this.siteRepo.save(site);

      const audit = AuditLog.create({
        tenantId,
        userId,
        action: 'SITE_TLS_PROVISIONED',
        resource: 'ProtectedSite',
        resourceId: site.id,
        metadata: {
          domain: site.domain.value,
          issuer: provisionResult.issuer,
          expiresAt: provisionResult.expiresAt.toISOString(),
          onboardingStatus: site.onboardingStatus,
        },
        ipAddress: clientIp,
      }).getValue();
      await this.auditRepo.save(audit);

      return Result.ok(toInstructionResponse(site));
    } else {
      const errorMsg = provisionResult.error || 'TLS certificate provisioning failed';
      site.markTlsFailed(errorMsg);
      await this.siteRepo.save(site);

      const audit = AuditLog.create({
        tenantId,
        userId,
        action: 'SITE_TLS_FAILED',
        resource: 'ProtectedSite',
        resourceId: site.id,
        metadata: {
          domain: site.domain.value,
          error: errorMsg,
          onboardingStatus: site.onboardingStatus,
        },
        ipAddress: clientIp,
      }).getValue();
      await this.auditRepo.save(audit);

      return Result.fail(errorMsg);
    }
  }
}

@Injectable()
export class ActivateSiteUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(ORIGIN_HEALTH_CHECKER) private readonly originHealthChecker: IOriginHealthChecker,
    @Inject(SITE_CONFIG_SYNC_CLIENT) private readonly syncClient: ISiteConfigSyncClient,
    @Inject(WAF_POLICY_REPOSITORY) private readonly policyRepo: IWafPolicyRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
  ) {}

  async execute(
    tenantId: string,
    siteId: string,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<OnboardingInstructionsResponseDto>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    if (site.onboardingStatus !== OnboardingStatus.HEALTH_CHECK) {
      return Result.fail(
        `Site must be in HEALTH_CHECK state to activate (current: ${site.onboardingStatus})`,
      );
    }

    // Run pre-activation origin health probe
    const healthResult = await this.originHealthChecker.checkOriginHealth(site.originUrl.value);

    if (healthResult.healthy) {
      const actRes = site.activate(OriginHealthStatus.HEALTHY);
      if (actRes.isFailure) {
        return Result.fail(actRes.getError());
      }

      // Sync active route config with enabled: true to WAF Gateway
      try {
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
          : undefined;

        const syncRes = await this.syncClient.syncSiteConfig({
          site_id: site.id,
          tenant_id: site.tenantId,
          domain: site.domain.value,
          origin_url: site.originUrl.value,
          enabled: true,
          config_version: site.configVersion,
          policy: policyPayload,
        });

        if (syncRes.acknowledged) {
          site.acknowledgeGatewaySync(syncRes.config_version);
        }
      } catch {
        // Non-blocking sync attempt
      }

      await this.siteRepo.save(site);

      const audit = AuditLog.create({
        tenantId,
        userId,
        action: 'SITE_ACTIVATED',
        resource: 'ProtectedSite',
        resourceId: site.id,
        metadata: {
          domain: site.domain.value,
          originUrl: site.originUrl.value,
          latencyMs: healthResult.latencyMs,
          statusCode: healthResult.statusCode,
          onboardingStatus: site.onboardingStatus,
        },
        ipAddress: clientIp,
      }).getValue();
      await this.auditRepo.save(audit);

      return Result.ok(toInstructionResponse(site));
    } else {
      const errorMsg =
        healthResult.error || `Origin health check failed (status ${healthResult.statusCode || 'timeout'})`;
      site.activate(OriginHealthStatus.UNHEALTHY);
      await this.siteRepo.save(site);

      const audit = AuditLog.create({
        tenantId,
        userId,
        action: 'SITE_ACTIVATION_FAILED',
        resource: 'ProtectedSite',
        resourceId: site.id,
        metadata: {
          domain: site.domain.value,
          originUrl: site.originUrl.value,
          error: errorMsg,
          onboardingStatus: site.onboardingStatus,
        },
        ipAddress: clientIp,
      }).getValue();
      await this.auditRepo.save(audit);

      return Result.fail(errorMsg);
    }
  }
}

@Injectable()
export class CheckSiteOriginHealthUseCase {
  constructor(
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(ORIGIN_HEALTH_CHECKER) private readonly originHealthChecker: IOriginHealthChecker,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
    @Optional() @Inject(NOTIFICATION_REPOSITORY) private readonly notificationRepo?: INotificationRepository,
  ) {}

  async execute(
    tenantId: string,
    siteId: string,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<SiteHealthCheckResponseDto>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    const healthResult = await this.originHealthChecker.checkOriginHealth(site.originUrl.value);
    const healthStatus = healthResult.healthy
      ? OriginHealthStatus.HEALTHY
      : OriginHealthStatus.UNHEALTHY;

    site.updateOriginHealth(healthStatus);
    await this.siteRepo.save(site);

    if (!healthResult.healthy && this.notificationRepo) {
      try {
        const notif = Notification.create(crypto.randomUUID(), {
          tenantId,
          siteId: site.id,
          severity: 'WARNING',
          type: 'ML_DEGRADED',
          title: `Origin Health Warning for ${site.domain.value}`,
          message:
            healthResult.error ||
            `Origin health probe failed with status ${healthResult.statusCode || 'unknown'}`,
          metadataJson: {
            domain: site.domain.value,
            originUrl: site.originUrl.value,
            latencyMs: healthResult.latencyMs,
            statusCode: healthResult.statusCode,
          },
        });
        await this.notificationRepo.save(notif);
      } catch {
        // Notification emission is non-blocking
      }
    }

    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'SITE_HEALTH_CHECKED',
      resource: 'ProtectedSite',
      resourceId: site.id,
      metadata: {
        domain: site.domain.value,
        originHealthStatus: healthStatus,
        healthy: healthResult.healthy,
        latencyMs: healthResult.latencyMs,
        statusCode: healthResult.statusCode,
      },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok({
      siteId: site.id,
      domain: site.domain.value,
      originUrl: site.originUrl.value,
      healthy: healthResult.healthy,
      statusCode: healthResult.statusCode,
      latencyMs: healthResult.latencyMs,
      originHealthStatus: site.originHealthStatus,
      lastHealthCheckAt: site.lastHealthCheckAt ? site.lastHealthCheckAt.toISOString() : null,
      error: healthResult.error,
    });
  }
}
