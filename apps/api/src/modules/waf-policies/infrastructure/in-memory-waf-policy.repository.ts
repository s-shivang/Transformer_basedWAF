import { WafPolicy, WafMode, MlFailureMode } from '../domain/waf-policy.entity';
import { PolicyThresholds } from '../domain/policy-thresholds.vo';
import { ScopedExclusion } from '../domain/scoped-exclusion.vo';
import { IWafPolicyRepository } from '../domain/waf-policy.repository.interface';

export class InMemoryWafPolicyRepository implements IWafPolicyRepository {
  private policies: Map<string, WafPolicy> = new Map();

  async findActiveBySite(tenantId: string, siteId: string): Promise<WafPolicy | null> {
    for (const p of this.policies.values()) {
      if (p.tenantId === tenantId && p.siteId === siteId && p.isActive) {
        return p;
      }
    }
    return null;
  }

  async findBySiteAndVersion(tenantId: string, siteId: string, version: number): Promise<WafPolicy | null> {
    for (const p of this.policies.values()) {
      if (p.tenantId === tenantId && p.siteId === siteId && p.version === version) {
        return p;
      }
    }
    return null;
  }

  async findHistoryBySite(tenantId: string, siteId: string): Promise<WafPolicy[]> {
    return Array.from(this.policies.values())
      .filter((p) => p.tenantId === tenantId && p.siteId === siteId)
      .sort((a, b) => b.version - a.version);
  }

  async save(policy: WafPolicy): Promise<void> {
    this.policies.set(policy.id, policy);
  }

  async deactivateActivePolicies(tenantId: string, siteId: string): Promise<void> {
    for (const p of this.policies.values()) {
      if (p.tenantId === tenantId && p.siteId === siteId && p.isActive) {
        p.deactivate();
      }
    }
  }

  clear() {
    this.policies.clear();
  }
}
