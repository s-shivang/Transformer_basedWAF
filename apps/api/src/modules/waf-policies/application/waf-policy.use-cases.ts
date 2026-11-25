import { Inject, Injectable, Optional } from '@nestjs/common';
import { IJobQueue } from '@shared/infrastructure/queues/job-queue.interface';
import { JOB_QUEUE_TOKEN, QUEUES, JOBS } from '@shared/infrastructure/queues/queue.constants';
import { Result } from '@shared/application/result';
import { WafPolicy, WafMode, MlFailureMode } from '../domain/waf-policy.entity';
import { PolicyThresholds } from '../domain/policy-thresholds.vo';
import { ScopedExclusion } from '../domain/scoped-exclusion.vo';
import {
  IWafPolicyRepository,
  WAF_POLICY_REPOSITORY,
} from '../domain/waf-policy.repository.interface';
import {
  IProtectedSiteRepository,
  PROTECTED_SITE_REPOSITORY,
} from '../../protected-sites/domain/protected-site.repository.interface';
import {
  IAuditLogRepository,
  AUDIT_LOG_REPOSITORY,
} from '../../identity/domain/identity.repository.interfaces';
import { AuditLog } from '../../identity/domain/audit-log.entity';
import { UpdateWafPolicyDto } from '../presentation/dtos/waf-policy.dto';

export function serializePolicy(policy: WafPolicy) {
  return {
    id: policy.id,
    tenantId: policy.tenantId,
    siteId: policy.siteId,
    name: policy.name,
    mode: policy.mode,
    mlEnabled: policy.mlEnabled,
    rulesEnabled: policy.rulesEnabled,
    challengeEnabled: policy.challengeEnabled,
    thresholds: {
      monitorThreshold: policy.thresholds.monitorThreshold,
      challengeThreshold: policy.thresholds.challengeThreshold,
      blockThreshold: policy.thresholds.blockThreshold,
    },
    mlFailureMode: policy.mlFailureMode,
    exclusions: policy.exclusions.map((e) => ({
      id: e.id,
      pathPrefix: e.pathPrefix,
      parameterName: e.parameterName,
      reason: e.reason,
      skipMl: e.skipMl,
      skipRules: e.skipRules,
      createdAt: e.createdAt.toISOString(),
    })),
    modelVersion: policy.modelVersion,
    version: policy.version,
    isActive: policy.isActive,
    updatedByUserId: policy.updatedByUserId,
    createdAt: policy.createdAt.toISOString(),
    updatedAt: policy.updatedAt.toISOString(),
  };
}

@Injectable()
export class GetSitePolicyUseCase {
  constructor(
    @Inject(WAF_POLICY_REPOSITORY) private readonly policyRepo: IWafPolicyRepository,
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
  ) {}

  async execute(tenantId: string, siteId: string): Promise<Result<any>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    const policy = await this.policyRepo.findActiveBySite(tenantId, siteId);
    if (!policy) {
      return Result.fail(`No active WAF policy found for site '${siteId}'`);
    }

    return Result.ok(serializePolicy(policy));
  }
}

@Injectable()
export class ListSitePolicyHistoryUseCase {
  constructor(
    @Inject(WAF_POLICY_REPOSITORY) private readonly policyRepo: IWafPolicyRepository,
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
  ) {}

  async execute(tenantId: string, siteId: string): Promise<Result<any[]>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    const history = await this.policyRepo.findHistoryBySite(tenantId, siteId);
    return Result.ok(history.map(serializePolicy));
  }
}

@Injectable()
export class UpdateSitePolicyUseCase {
  constructor(
    @Inject(WAF_POLICY_REPOSITORY) private readonly policyRepo: IWafPolicyRepository,
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
    @Optional() @Inject(JOB_QUEUE_TOKEN) private readonly jobQueue?: IJobQueue,
  ) {}

  async execute(
    tenantId: string,
    siteId: string,
    dto: UpdateWafPolicyDto,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<any>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    const currentActive = await this.policyRepo.findActiveBySite(tenantId, siteId);
    if (!currentActive) {
      return Result.fail(`No active WAF policy found for site '${siteId}' to update`);
    }

    // Merge or validate thresholds
    let newThresholds: PolicyThresholds | undefined;
    if (
      dto.monitorThreshold !== undefined ||
      dto.challengeThreshold !== undefined ||
      dto.blockThreshold !== undefined
    ) {
      const monitor = dto.monitorThreshold ?? currentActive.thresholds.monitorThreshold;
      const challenge = dto.challengeThreshold ?? currentActive.thresholds.challengeThreshold;
      const block = dto.blockThreshold ?? currentActive.thresholds.blockThreshold;

      const threshRes = PolicyThresholds.create(monitor, challenge, block);
      if (threshRes.isFailure) {
        return Result.fail(threshRes.getError());
      }
      newThresholds = threshRes.getValue();
    }

    // Validate exclusions if supplied
    let newExclusions: ScopedExclusion[] | undefined;
    if (dto.exclusions !== undefined) {
      newExclusions = [];
      for (const excDto of dto.exclusions) {
        const excRes = ScopedExclusion.create({
          pathPrefix: excDto.pathPrefix,
          parameterName: excDto.parameterName,
          reason: excDto.reason,
          skipMl: excDto.skipMl,
          skipRules: excDto.skipRules,
        });
        if (excRes.isFailure) {
          return Result.fail(excRes.getError());
        }
        newExclusions.push(excRes.getValue());
      }
    }

    // Deactivate current active policy
    await this.policyRepo.deactivateActivePolicies(tenantId, siteId);

    // Create next version
    const nextPolicy = currentActive.createNextVersion(
      {
        name: dto.name,
        mode: dto.mode,
        mlEnabled: dto.mlEnabled,
        rulesEnabled: dto.rulesEnabled,
        challengeEnabled: dto.challengeEnabled,
        thresholds: newThresholds,
        mlFailureMode: dto.mlFailureMode,
        exclusions: newExclusions,
      },
      userId,
    );

    await this.policyRepo.save(nextPolicy);

    // Record Audit Log
    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'WAF_POLICY_UPDATED',
      resource: 'WafPolicy',
      resourceId: nextPolicy.id,
      metadata: {
        siteId,
        previousVersion: currentActive.version,
        newVersion: nextPolicy.version,
        mode: nextPolicy.mode,
      },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    if (this.jobQueue) {
      await this.jobQueue.enqueue(QUEUES.POLICY_SYNC, JOBS.SYNC_POLICY, {
        tenantId,
        siteId,
        version: nextPolicy.version,
        effectivePolicy: serializePolicy(nextPolicy),
      });
    }

    return Result.ok(serializePolicy(nextPolicy));
  }
}

@Injectable()
export class RollbackSitePolicyUseCase {
  constructor(
    @Inject(WAF_POLICY_REPOSITORY) private readonly policyRepo: IWafPolicyRepository,
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
    @Optional() @Inject(JOB_QUEUE_TOKEN) private readonly jobQueue?: IJobQueue,
  ) {}

  async execute(
    tenantId: string,
    siteId: string,
    targetVersion: number,
    userId?: string,
    clientIp?: string,
  ): Promise<Result<any>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    const currentActive = await this.policyRepo.findActiveBySite(tenantId, siteId);
    if (!currentActive) {
      return Result.fail(`No active WAF policy found for site '${siteId}'`);
    }

    if (currentActive.version === targetVersion) {
      return Result.fail(`Version ${targetVersion} is already the currently active policy`);
    }

    const targetHistorical = await this.policyRepo.findBySiteAndVersion(tenantId, siteId, targetVersion);
    if (!targetHistorical) {
      return Result.fail(`Historical policy version ${targetVersion} not found for site '${siteId}'`);
    }

    // Deactivate current active policy
    await this.policyRepo.deactivateActivePolicies(tenantId, siteId);

    // Create a new rollback version (currentActive.version + 1) restoring target snapshot
    const rollbackPolicy = WafPolicy.createRollbackVersion(currentActive, targetHistorical, userId);
    await this.policyRepo.save(rollbackPolicy);

    // Record Audit Log
    const audit = AuditLog.create({
      tenantId,
      userId,
      action: 'WAF_POLICY_ROLLED_BACK',
      resource: 'WafPolicy',
      resourceId: rollbackPolicy.id,
      metadata: {
        siteId,
        rolledBackFromVersion: currentActive.version,
        rolledBackToVersion: targetHistorical.version,
        newVersion: rollbackPolicy.version,
      },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    if (this.jobQueue) {
      await this.jobQueue.enqueue(QUEUES.POLICY_SYNC, JOBS.SYNC_POLICY, {
        tenantId,
        siteId,
        version: rollbackPolicy.version,
        effectivePolicy: serializePolicy(rollbackPolicy),
      });
    }

    return Result.ok(serializePolicy(rollbackPolicy));
  }
}

@Injectable()
export class GetEffectiveGatewayPolicyUseCase {
  constructor(
    @Inject(WAF_POLICY_REPOSITORY) private readonly policyRepo: IWafPolicyRepository,
    @Inject(PROTECTED_SITE_REPOSITORY) private readonly siteRepo: IProtectedSiteRepository,
  ) {}

  async execute(tenantId: string, siteId: string): Promise<Result<any>> {
    const site = await this.siteRepo.findById(tenantId, siteId);
    if (!site) {
      return Result.fail(`Protected site '${siteId}' not found`);
    }

    const policy = await this.policyRepo.findActiveBySite(tenantId, siteId);
    if (!policy) {
      return Result.fail(`No active WAF policy found for site '${siteId}'`);
    }

    return Result.ok({
      siteId: site.id,
      domain: site.domain.value,
      originUrl: site.originUrl.value,
      status: site.status,
      policyVersion: policy.version,
      mode: policy.mode,
      ml_enabled: policy.mlEnabled,
      rules_enabled: policy.rulesEnabled,
      challenge_enabled: policy.challengeEnabled,
      ml_failure_mode: policy.mlFailureMode,
      thresholds: {
        fast_pass_allow: 0.04,
        monitor_alert: policy.thresholds.monitorThreshold,
        challenge: policy.thresholds.challengeThreshold,
        block: policy.thresholds.blockThreshold,
      },
      exclusions: policy.exclusions.map((e) => ({
        path_prefix: e.pathPrefix,
        parameter_name: e.parameterName,
        skip_ml: e.skipMl,
        skip_rules: e.skipRules,
      })),
    });
  }
}
