import { ProtectedSite } from './protected-site.entity';
import { SiteDomain } from './site-domain.vo';

export const PROTECTED_SITE_REPOSITORY = Symbol('IProtectedSiteRepository');

export interface IProtectedSiteRepository {
  findById(tenantId: string, siteId: string): Promise<ProtectedSite | null>;
  findByDomain(tenantId: string, domain: SiteDomain): Promise<ProtectedSite | null>;
  findAllByTenant(tenantId: string): Promise<ProtectedSite[]>;
  save(site: ProtectedSite): Promise<void>;
  delete(tenantId: string, siteId: string): Promise<void>;
  exists(tenantId: string, domain: SiteDomain): Promise<boolean>;
}
