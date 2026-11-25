import { Injectable, Logger } from '@nestjs/common';
import {
  ISiteConfigSyncClient,
  GatewaySiteSyncPayload,
  GatewaySiteSyncResult,
} from '../../domain/site-config-sync.interface';

@Injectable()
export class HttpSiteConfigSyncClient implements ISiteConfigSyncClient {
  private readonly logger = new Logger(HttpSiteConfigSyncClient.name);
  private readonly gatewayUrl: string;
  private readonly adminKey: string;

  constructor() {
    this.gatewayUrl = (
      process.env.WAF_GATEWAY_URL ||
      process.env.WAF_GATEWAY_ADMIN_URL ||
      process.env.WAF_GATEWAY_SYNC_URL ||
      'http://127.0.0.1:8001'
    ).replace(/\/+$/, '');
    this.adminKey = process.env.WAF_ADMIN_KEY || 'waf-admin-secret-key-local';
  }

  async syncSiteConfig(payload: GatewaySiteSyncPayload): Promise<GatewaySiteSyncResult> {
    const url = `${this.gatewayUrl}/_waf/sites/sync`;
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-WAF-Admin-Key': this.adminKey,
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errText = await response.text();
        this.logger.error(`Gateway sync failed [${response.status}]: ${errText}`);
        return {
          acknowledged: false,
          site_id: payload.site_id,
          domain: payload.domain,
          config_version: payload.config_version,
          error: `Gateway returned status ${response.status}: ${errText}`,
        };
      }

      const data = await response.json();
      return {
        acknowledged: Boolean(data.acknowledged),
        site_id: data.site_id || payload.site_id,
        domain: data.domain || payload.domain,
        config_version: data.config_version || payload.config_version,
        active_sites_count: data.active_sites_count,
      };
    } catch (err: any) {
      this.logger.error(`Failed to reach WAF Gateway at ${url}: ${err.message}`);
      return {
        acknowledged: false,
        site_id: payload.site_id,
        domain: payload.domain,
        config_version: payload.config_version,
        error: `Gateway connection error: ${err.message}`,
      };
    }
  }

  async removeSiteConfig(domain: string): Promise<{ removed: boolean; error?: string }> {
    const cleanDomain = encodeURIComponent(domain.trim().toLowerCase());
    const url = `${this.gatewayUrl}/_waf/sites/${cleanDomain}`;
    try {
      const response = await fetch(url, {
        method: 'DELETE',
        headers: {
          'X-WAF-Admin-Key': this.adminKey,
        },
      });

      if (!response.ok) {
        const errText = await response.text();
        return { removed: false, error: `Gateway returned status ${response.status}: ${errText}` };
      }

      const data = await response.json();
      return { removed: Boolean(data.removed) };
    } catch (err: any) {
      return { removed: false, error: `Gateway connection error: ${err.message}` };
    }
  }
}
