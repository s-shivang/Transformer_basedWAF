import { ProtectedSite } from '../domain/protected-site.entity';
import { SiteDomain } from '../domain/site-domain.vo';
import { IProtectedSiteRepository } from '../domain/protected-site.repository.interface';

export class InMemoryProtectedSiteRepository implements IProtectedSiteRepository {
  private sites: Map<string, ProtectedSite> = new Map();

  async findById(tenantId: string, siteId: string): Promise<ProtectedSite | null> {
    const site = this.sites.get(siteId);
    if (!site || site.tenantId !== tenantId) return null;
    return site;
  }

  async findByDomain(tenantId: string, domain: SiteDomain): Promise<ProtectedSite | null> {
    for (const site of this.sites.values()) {
      if (site.tenantId === tenantId && site.domain.value === domain.value) {
        return site;
      }
    }
    return null;
  }

  async findGlobalByDomain(domain: SiteDomain): Promise<ProtectedSite | null> {
    for (const site of this.sites.values()) {
      if (site.domain.value === domain.value) {
        return site;
      }
    }
    return null;
  }

  async findAllByTenant(tenantId: string): Promise<ProtectedSite[]> {
    return Array.from(this.sites.values()).filter((s) => s.tenantId === tenantId);
  }

  async countByTenant(tenantId: string): Promise<number> {
    return Array.from(this.sites.values()).filter((s) => s.tenantId === tenantId).length;
  }

  async save(site: ProtectedSite): Promise<void> {
    this.sites.set(site.id, site);
  }

  async delete(tenantId: string, siteId: string): Promise<void> {
    const site = this.sites.get(siteId);
    if (site && site.tenantId === tenantId) {
      this.sites.delete(siteId);
    }
  }

  async exists(tenantId: string, domain: SiteDomain): Promise<boolean> {
    const site = await this.findByDomain(tenantId, domain);
    return site !== null;
  }

  clear() {
    this.sites.clear();
  }
}
