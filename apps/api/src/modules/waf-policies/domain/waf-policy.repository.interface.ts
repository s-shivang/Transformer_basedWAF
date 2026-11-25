import { WafPolicy } from './waf-policy.entity';

export const WAF_POLICY_REPOSITORY = Symbol('IWafPolicyRepository');

export interface IWafPolicyRepository {
  findActiveBySite(tenantId: string, siteId: string): Promise<WafPolicy | null>;
  findBySiteAndVersion(tenantId: string, siteId: string, version: number): Promise<WafPolicy | null>;
  findHistoryBySite(tenantId: string, siteId: string): Promise<WafPolicy[]>;
  save(policy: WafPolicy): Promise<void>;
  deactivateActivePolicies(tenantId: string, siteId: string): Promise<void>;
}
