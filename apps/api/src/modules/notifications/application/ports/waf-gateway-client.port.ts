export interface PolicySyncResult {
  success: boolean;
  statusCode?: number;
  error?: string;
}

export interface IWafGatewayClient {
  syncPolicy(siteId: string, effectivePolicy: any): Promise<PolicySyncResult>;
}

export const WAF_GATEWAY_CLIENT = 'WAF_GATEWAY_CLIENT';
