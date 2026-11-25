import { Injectable } from '@nestjs/common';
import {
  IWafGatewayClient,
  PolicySyncResult,
} from '../../application/ports/waf-gateway-client.port';

@Injectable()
export class HttpWafGatewayClient implements IWafGatewayClient {
  private readonly gatewayUrl: string;
  private readonly adminKey: string;

  constructor() {
    this.gatewayUrl = process.env.WAF_GATEWAY_ADMIN_URL || process.env.WAF_GATEWAY_URL || 'http://localhost:8001';
    this.adminKey = process.env.WAF_ADMIN_KEY || 'waf-admin-secret-key-local';
  }

  async syncPolicy(siteId: string, effectivePolicy: any): Promise<PolicySyncResult> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const mode = (effectivePolicy.mode || 'MONITOR').toLowerCase();
      const payload: any = {
        inspection_mode: mode === 'disabled' ? 'disabled' : mode === 'blocking' ? 'blocking' : mode === 'strict' ? 'strict' : 'monitor',
        rules_enabled: effectivePolicy.rulesEnabled,
        ml_enabled: effectivePolicy.mlEnabled,
        ml_failure_mode: (effectivePolicy.mlFailureMode || 'FAIL_OPEN').toLowerCase(),
        thresholds: {
          block: effectivePolicy.blockThreshold,
          challenge: effectivePolicy.challengeThreshold,
          monitor: effectivePolicy.monitorThreshold,
        },
      };

      const response = await fetch(`${this.gatewayUrl}/_waf/policy`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-WAF-Admin-Key': this.adminKey,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      return {
        success: response.ok,
        statusCode: response.status,
        error: response.ok ? undefined : `HTTP ${response.status}`,
      };
    } catch (err: any) {
      return {
        success: false,
        error: err.message || 'Gateway connection error',
      };
    }
  }
}

export class InMemoryWafGatewayClient implements IWafGatewayClient {
  public syncedPolicies: { siteId: string; policy: any }[] = [];
  public shouldFail = false;

  async syncPolicy(siteId: string, effectivePolicy: any): Promise<PolicySyncResult> {
    this.syncedPolicies.push({ siteId, policy: effectivePolicy });
    if (this.shouldFail) {
      return {
        success: false,
        statusCode: 503,
        error: 'Simulated gateway offline',
      };
    }
    return { success: true, statusCode: 200 };
  }

  clear() {
    this.syncedPolicies = [];
    this.shouldFail = false;
  }
}
