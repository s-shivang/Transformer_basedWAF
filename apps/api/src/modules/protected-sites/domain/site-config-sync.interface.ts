export const SITE_CONFIG_SYNC_CLIENT = Symbol('ISiteConfigSyncClient');

export interface GatewayPolicyPayload {
  mode: string;
  block_threshold: number;
  challenge_threshold: number;
  monitor_threshold: number;
  ml_enabled: boolean;
  rules_enabled: boolean;
  challenge_enabled: boolean;
  exclusions: any[];
}

export interface GatewaySiteSyncPayload {
  site_id: string;
  tenant_id: string;
  domain: string;
  origin_url: string;
  enabled: boolean;
  config_version: number;
  policy?: GatewayPolicyPayload;
  force_rollback?: boolean;
}

export interface GatewaySiteSyncResult {
  acknowledged: boolean;
  site_id: string;
  domain: string;
  config_version: number;
  active_sites_count?: number;
  error?: string;
}

export interface ISiteConfigSyncClient {
  syncSiteConfig(payload: GatewaySiteSyncPayload): Promise<GatewaySiteSyncResult>;
  removeSiteConfig(domain: string): Promise<{ removed: boolean; error?: string }>;
}
