import { Injectable } from '@nestjs/common';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import { WafPolicy, WafMode, MlFailureMode } from '../domain/waf-policy.entity';
import { PolicyThresholds } from '../domain/policy-thresholds.vo';
import { ScopedExclusion } from '../domain/scoped-exclusion.vo';
import { IWafPolicyRepository } from '../domain/waf-policy.repository.interface';

@Injectable()
export class PrismaWafPolicyRepository implements IWafPolicyRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findActiveBySite(tenantId: string, siteId: string): Promise<WafPolicy | null> {
    const record = await this.prisma.wafPolicy.findFirst({
      where: { tenantId, siteId, isActive: true },
      orderBy: { version: 'desc' },
    });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findBySiteAndVersion(tenantId: string, siteId: string, version: number): Promise<WafPolicy | null> {
    const record = await this.prisma.wafPolicy.findFirst({
      where: { tenantId, siteId, version },
    });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findHistoryBySite(tenantId: string, siteId: string): Promise<WafPolicy[]> {
    const records = await this.prisma.wafPolicy.findMany({
      where: { tenantId, siteId },
      orderBy: { version: 'desc' },
    });
    return records.map((r) => this.toDomain(r));
  }

  async save(policy: WafPolicy): Promise<void> {
    const rawExclusions = policy.exclusions.map((e) => ({
      id: e.id,
      pathPrefix: e.pathPrefix,
      parameterName: e.parameterName,
      reason: e.reason,
      skipMl: e.skipMl,
      skipRules: e.skipRules,
      createdAt: e.createdAt.toISOString(),
    }));

    await this.prisma.wafPolicy.upsert({
      where: { id: policy.id },
      create: {
        id: policy.id,
        tenantId: policy.tenantId,
        siteId: policy.siteId,
        name: policy.name,
        mode: policy.mode as any,
        mlEnabled: policy.mlEnabled,
        rulesEnabled: policy.rulesEnabled,
        challengeEnabled: policy.challengeEnabled,
        monitorThreshold: policy.thresholds.monitorThreshold,
        challengeThreshold: policy.thresholds.challengeThreshold,
        blockThreshold: policy.thresholds.blockThreshold,
        mlFailureMode: policy.mlFailureMode as any,
        exclusionsJson: rawExclusions as any,
        modelVersion: policy.modelVersion,
        version: policy.version,
        isActive: policy.isActive,
        updatedByUserId: policy.updatedByUserId,
        createdAt: policy.createdAt,
        updatedAt: policy.updatedAt,
      },
      update: {
        isActive: policy.isActive,
        updatedAt: policy.updatedAt,
      },
    });
  }

  async deactivateActivePolicies(tenantId: string, siteId: string): Promise<void> {
    await this.prisma.wafPolicy.updateMany({
      where: { tenantId, siteId, isActive: true },
      data: { isActive: false },
    });
  }

  private toDomain(record: any): WafPolicy {
    const thresholds = PolicyThresholds.create(
      record.monitorThreshold,
      record.challengeThreshold,
      record.blockThreshold,
    ).getValue();

    const rawList = Array.isArray(record.exclusionsJson) ? record.exclusionsJson : [];
    const exclusions = rawList.map((e: any) =>
      ScopedExclusion.create({
        id: e.id,
        pathPrefix: e.pathPrefix,
        parameterName: e.parameterName,
        reason: e.reason,
        skipMl: e.skipMl,
        skipRules: e.skipRules,
        createdAt: e.createdAt ? new Date(e.createdAt) : undefined,
      }).getValue(),
    );

    return WafPolicy.reconstitute(record.id, {
      tenantId: record.tenantId,
      siteId: record.siteId,
      name: record.name,
      mode: record.mode as WafMode,
      mlEnabled: record.mlEnabled,
      rulesEnabled: record.rulesEnabled,
      challengeEnabled: record.challengeEnabled,
      thresholds,
      mlFailureMode: record.mlFailureMode as MlFailureMode,
      exclusions,
      modelVersion: record.modelVersion,
      version: record.version,
      isActive: record.isActive,
      updatedByUserId: record.updatedByUserId,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    });
  }
}
