import { SiteDomain } from './site-domain.vo';
import { OriginUrl } from './origin-url.vo';
import { ProtectedSite, SiteStatus } from './protected-site.entity';

describe('Protected Sites Domain Value Objects & Entity', () => {
  describe('SiteDomain VO', () => {
    it('accepts valid FQDNs', () => {
      const res = SiteDomain.create('api.example.com');
      expect(res.isSuccess).toBe(true);
      expect(res.getValue().value).toBe('api.example.com');
    });

    it('normalizes uppercase to lowercase and trims whitespace', () => {
      const res = SiteDomain.create('  SHOP.MYSTORE.CO.UK  ');
      expect(res.isSuccess).toBe(true);
      expect(res.getValue().value).toBe('shop.mystore.co.uk');
    });

    it('rejects schemes in domain', () => {
      const res = SiteDomain.create('https://example.com');
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('scheme');
    });

    it('rejects ports in domain', () => {
      const res = SiteDomain.create('example.com:8080');
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('port');
    });

    it('rejects paths in domain', () => {
      const res = SiteDomain.create('example.com/api');
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('path');
    });

    it('rejects wildcards in domain', () => {
      const res = SiteDomain.create('*.example.com');
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('Wildcard');
    });

    it('rejects invalid domain formats', () => {
      const res = SiteDomain.create('not a domain!@#');
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('Invalid domain format');
    });
  });

  describe('OriginUrl VO (SSRF Protection)', () => {
    it('accepts valid https and http URLs', () => {
      const res = OriginUrl.create('https://origin.internal.net:8443');
      expect(res.isSuccess).toBe(true);
      expect(res.getValue().value).toBe('https://origin.internal.net:8443');
    });

    it('rejects non-http/https protocols', () => {
      const res = OriginUrl.create('ftp://origin.internal.net');
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('http:// or https://');
    });

    it('rejects AWS/GCP/Azure link-local metadata IP (169.254.169.254)', () => {
      const res = OriginUrl.create('http://169.254.169.254/latest/meta-data/');
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('Forbidden origin host');
    });

    it('rejects metadata.google.internal', () => {
      const res = OriginUrl.create('http://metadata.google.internal/computeMetadata/v1/');
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('Forbidden origin host');
    });

    it('rejects 0.0.0.0 and Tailscale metadata IP (100.100.100.200)', () => {
      const res1 = OriginUrl.create('http://0.0.0.0:8000');
      const res2 = OriginUrl.create('http://100.100.100.200');
      expect(res1.isFailure).toBe(true);
      expect(res2.isFailure).toBe(true);
    });
  });

  describe('ProtectedSite Entity', () => {
    it('creates active site with valid domain and origin', () => {
      const domain = SiteDomain.create('app.tenant.com').getValue();
      const origin = OriginUrl.create('https://internal-lb.aws.local').getValue();

      const siteRes = ProtectedSite.create({
        tenantId: 'tenant-123',
        name: 'Main App',
        domain,
        originUrl: origin,
      });

      expect(siteRes.isSuccess).toBe(true);
      const site = siteRes.getValue();
      expect(site.status).toBe(SiteStatus.ACTIVE);
      expect(site.name).toBe('Main App');
      expect(site.domain.value).toBe('app.tenant.com');
      expect(site.originUrl.value).toBe('https://internal-lb.aws.local');
    });

    it('updates site name, status, and origin', () => {
      const domain = SiteDomain.create('app.tenant.com').getValue();
      const origin = OriginUrl.create('https://old.local').getValue();
      const site = ProtectedSite.create({
        tenantId: 'tenant-123',
        name: 'Old Name',
        domain,
        originUrl: origin,
      }).getValue();

      const newOrigin = OriginUrl.create('https://new.local').getValue();
      site.update({
        name: 'Updated Name',
        status: SiteStatus.PAUSED,
        originUrl: newOrigin,
      });

      expect(site.name).toBe('Updated Name');
      expect(site.status).toBe(SiteStatus.PAUSED);
      expect(site.originUrl.value).toBe('https://new.local');
    });
  });
});
