import { TenantSlug } from './tenant-slug.vo';
import { TenantId } from './tenant-id.vo';
import { Tenant, TenantTier, TenantStatus } from './tenant.entity';

describe('Tenant Domain Model', () => {
  describe('TenantSlug Value Object', () => {
    it('should create a valid tenant slug', () => {
      const result = TenantSlug.create('acme-corp');
      expect(result.isSuccess).toBe(true);
      expect(result.getValue().value).toBe('acme-corp');
    });

    it('should normalize uppercase to lowercase', () => {
      const result = TenantSlug.create('AcMe-CoRp');
      expect(result.isSuccess).toBe(true);
      expect(result.getValue().value).toBe('acme-corp');
    });

    it('should fail if slug is too short (< 3 chars)', () => {
      const result = TenantSlug.create('ab');
      expect(result.isFailure).toBe(true);
      expect(result.getError()).toContain('at least 3 characters');
    });

    it('should fail if slug contains invalid special characters', () => {
      const result = TenantSlug.create('acme_corp$');
      expect(result.isFailure).toBe(true);
      expect(result.getError()).toContain('only lowercase alphanumeric');
    });

    it('should fail if slug starts or ends with a hyphen', () => {
      expect(TenantSlug.create('-acme').isFailure).toBe(true);
      expect(TenantSlug.create('acme-').isFailure).toBe(true);
    });

    it('should correctly evaluate value object equality', () => {
      const slug1 = TenantSlug.create('acme-corp').getValue();
      const slug2 = TenantSlug.create('acme-corp').getValue();
      const slug3 = TenantSlug.create('other-corp').getValue();
      expect(slug1.equals(slug2)).toBe(true);
      expect(slug1.equals(slug3)).toBe(false);
    });
  });

  describe('Tenant Entity & Site Quota Invariants', () => {
    it('should create a valid tenant entity with default maxSites = 5', () => {
      const slug = TenantSlug.create('acme-corp').getValue();
      const result = Tenant.create({
        name: 'Acme Corporation',
        slug,
        tier: TenantTier.PRO,
      });

      expect(result.isSuccess).toBe(true);
      const tenant = result.getValue();
      expect(tenant.name).toBe('Acme Corporation');
      expect(tenant.slug.value).toBe('acme-corp');
      expect(tenant.tier).toBe(TenantTier.PRO);
      expect(tenant.status).toBe(TenantStatus.ACTIVE);
      expect(tenant.maxSites).toBe(5);
      expect(tenant.id).toBeDefined();
    });

    it('should accept custom initial maxSites within bounds (1..100)', () => {
      const slug = TenantSlug.create('custom-quota').getValue();
      const result = Tenant.create({
        name: 'Custom Quota Corp',
        slug,
        maxSites: 25,
      });

      expect(result.isSuccess).toBe(true);
      expect(result.getValue().maxSites).toBe(25);
    });

    it('should update site quota within allowed bounds', () => {
      const slug = TenantSlug.create('quota-update').getValue();
      const tenant = Tenant.create({ name: 'Quota Update Corp', slug }).getValue();

      expect(tenant.updateSiteQuota(12).isSuccess).toBe(true);
      expect(tenant.maxSites).toBe(12);

      expect(tenant.updateSiteQuota(100).isSuccess).toBe(true);
      expect(tenant.maxSites).toBe(100);

      expect(tenant.updateSiteQuota(1).isSuccess).toBe(true);
      expect(tenant.maxSites).toBe(1);
    });

    it('should reject invalid site quotas (< 1, > 100, NaN)', () => {
      const slug = TenantSlug.create('quota-invalid').getValue();
      const tenant = Tenant.create({ name: 'Invalid Quota Corp', slug }).getValue();

      expect(tenant.updateSiteQuota(0).isFailure).toBe(true);
      expect(tenant.updateSiteQuota(-10).isFailure).toBe(true);
      expect(tenant.updateSiteQuota(101).isFailure).toBe(true);
      expect(tenant.updateSiteQuota(NaN).isFailure).toBe(true);
      expect(tenant.updateSiteQuota(undefined as any).isFailure).toBe(true);
    });

    it('should fail when tenant name is empty', () => {
      const slug = TenantSlug.create('acme-corp').getValue();
      const result = Tenant.create({
        name: '',
        slug,
      });
      expect(result.isFailure).toBe(true);
      expect(result.getError()).toContain('name cannot be empty');
    });

    it('should allow status transitions', () => {
      const slug = TenantSlug.create('acme-corp').getValue();
      const tenant = Tenant.create({ name: 'Acme', slug }).getValue();

      tenant.suspend();
      expect(tenant.status).toBe(TenantStatus.SUSPENDED);

      tenant.activate();
      expect(tenant.status).toBe(TenantStatus.ACTIVE);

      tenant.delete();
      expect(tenant.status).toBe(TenantStatus.DELETED);

      // Cannot activate a deleted tenant
      const reactivate = tenant.activate();
      expect(reactivate.isFailure).toBe(true);
    });
  });
});
