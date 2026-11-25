import { Injectable } from '@nestjs/common';
import {
  ISiteConfigSyncClient,
  GatewaySiteSyncPayload,
  GatewaySiteSyncResult,
} from '../../domain/site-config-sync.interface';

@Injectable()
export class InMemorySiteConfigSyncClient implements ISiteConfigSyncClient {
  public syncedConfigs: Map<string, GatewaySiteSyncPayload> = new Map();
  public removedDomains: Set<string> = new Set();
  public shouldFail = false;
  public failureMessage = 'Simulated gateway sync failure';

  public setShouldFail(fail: boolean, msg?: string) {
    this.shouldFail = fail;
    if (msg) this.failureMessage = msg;
  }

  public clear() {
    this.syncedConfigs.clear();
    this.removedDomains.clear();
    this.shouldFail = false;
    this.failureMessage = 'Simulated gateway sync failure';
  }

  async syncSiteConfig(payload: GatewaySiteSyncPayload): Promise<GatewaySiteSyncResult> {
    if (this.shouldFail) {
      return {
        acknowledged: false,
        site_id: payload.site_id,
        domain: payload.domain,
        config_version: payload.config_version,
        error: this.failureMessage,
      };
    }

    const domainKey = payload.domain.trim().toLowerCase();
    this.syncedConfigs.set(domainKey, payload);
    this.removedDomains.delete(domainKey);

    return {
      acknowledged: true,
      site_id: payload.site_id,
      domain: domainKey,
      config_version: payload.config_version,
      active_sites_count: this.syncedConfigs.size,
    };
  }

  async removeSiteConfig(domain: string): Promise<{ removed: boolean; error?: string }> {
    const domainKey = domain.trim().toLowerCase();
    const existed = this.syncedConfigs.delete(domainKey);
    this.removedDomains.add(domainKey);
    return { removed: existed };
  }
}
