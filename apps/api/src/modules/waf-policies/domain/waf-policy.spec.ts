import { PolicyThresholds } from './policy-thresholds.vo';
import { ScopedExclusion } from './scoped-exclusion.vo';
import { WafPolicy, WafMode, MlFailureMode } from './waf-policy.entity';

describe('WAF Policy Domain Value Objects & Entity', () => {
  describe('PolicyThresholds VO', () => {
    it('creates valid default thresholds (0.05, 0.50, 0.85)', () => {
      const res = PolicyThresholds.create(0.05, 0.50, 0.85);
      expect(res.isSuccess).toBe(true);
      const val = res.getValue();
      expect(val.monitorThreshold).toBe(0.05);
      expect(val.challengeThreshold).toBe(0.50);
      expect(val.blockThreshold).toBe(0.85);
    });

    it('rejects monitor >= challenge', () => {
      const res = PolicyThresholds.create(0.60, 0.50, 0.85);
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('challengeThreshold must be strictly greater than monitorThreshold');
    });

    it('rejects challenge >= block', () => {
      const res = PolicyThresholds.create(0.05, 0.90, 0.85);
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('blockThreshold must be strictly greater than challengeThreshold');
    });

    it('rejects out of range thresholds', () => {
      const res1 = PolicyThresholds.create(-0.01, 0.50, 0.85);
      const res2 = PolicyThresholds.create(0.05, 0.50, 1.05);
      expect(res1.isFailure).toBe(true);
      expect(res2.isFailure).toBe(true);
    });
  });

  describe('ScopedExclusion VO', () => {
    it('creates valid scoped exclusion with leading slash and reason', () => {
      const res = ScopedExclusion.create({
        pathPrefix: '/api/v1/webhooks',
        parameterName: 'payload',
        reason: 'Payment webhook sends JSON blob with SQL-like tokens',
        skipMl: true,
        skipRules: false,
      });

      expect(res.isSuccess).toBe(true);
      const exc = res.getValue();
      expect(exc.pathPrefix).toBe('/api/v1/webhooks');
      expect(exc.parameterName).toBe('payload');
      expect(exc.reason).toBe('Payment webhook sends JSON blob with SQL-like tokens');
      expect(exc.skipMl).toBe(true);
      expect(exc.skipRules).toBe(false);
    });

    it('rejects path without leading slash', () => {
      const res = ScopedExclusion.create({
        pathPrefix: 'api/v1/webhooks',
        reason: 'Valid justification reason',
      });
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('leading slash');
    });

    it('rejects broad wildcard full-site bypass (* and /*)', () => {
      const res1 = ScopedExclusion.create({
        pathPrefix: '*',
        reason: 'Bypass all site traffic',
      });
      const res2 = ScopedExclusion.create({
        pathPrefix: '/*',
        reason: 'Bypass all site traffic',
      });
      expect(res1.isFailure).toBe(true);
      expect(res2.isFailure).toBe(true);
      expect(res2.getError()).toContain('broad wildcard');
    });

    it('rejects empty or too short reason (< 5 chars)', () => {
      const res = ScopedExclusion.create({
        pathPrefix: '/login',
        reason: 'test',
      });
      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('detailed justification reason');
    });
  });

  describe('WafPolicy Entity & Versioning Lifecycle', () => {
    it('creates default safe v1 MONITOR policy', () => {
      const policy = WafPolicy.createDefault('tenant-1', 'site-1', 'user-1');

      expect(policy.version).toBe(1);
      expect(policy.isActive).toBe(true);
      expect(policy.mode).toBe(WafMode.MONITOR);
      expect(policy.mlEnabled).toBe(true);
      expect(policy.rulesEnabled).toBe(true);
      expect(policy.challengeEnabled).toBe(true);
      expect(policy.mlFailureMode).toBe(MlFailureMode.FAIL_OPEN);
      expect(policy.thresholds.monitorThreshold).toBe(0.05);
      expect(policy.thresholds.challengeThreshold).toBe(0.50);
      expect(policy.thresholds.blockThreshold).toBe(0.85);
      expect(policy.exclusions).toEqual([]);
    });

    it('createNextVersion increments version number and updates settings', () => {
      const v1 = WafPolicy.createDefault('tenant-1', 'site-1', 'user-1');
      const newThresholds = PolicyThresholds.create(0.10, 0.60, 0.90).getValue();
      const exclusion = ScopedExclusion.create({
        pathPrefix: '/search',
        reason: 'Search parameter triggers harmless false positives',
      }).getValue();

      const v2 = v1.createNextVersion(
        {
          mode: WafMode.BLOCKING,
          thresholds: newThresholds,
          exclusions: [exclusion],
        },
        'user-2',
      );

      expect(v2.version).toBe(2);
      expect(v2.isActive).toBe(true);
      expect(v2.mode).toBe(WafMode.BLOCKING);
      expect(v2.thresholds.blockThreshold).toBe(0.90);
      expect(v2.exclusions.length).toBe(1);
      expect(v2.updatedByUserId).toBe('user-2');
    });

    it('createRollbackVersion creates next version restoring historical snapshot', () => {
      const v1 = WafPolicy.createDefault('tenant-1', 'site-1', 'user-1');
      const v2 = v1.createNextVersion({ mode: WafMode.BLOCKING }, 'user-2');

      // Now rollback to v1: should create v3 with v1 mode (MONITOR)
      const v3 = WafPolicy.createRollbackVersion(v2, v1, 'user-admin');

      expect(v3.version).toBe(3);
      expect(v3.isActive).toBe(true);
      expect(v3.mode).toBe(WafMode.MONITOR);
      expect(v3.updatedByUserId).toBe('user-admin');
      expect(v3.name).toContain('Rollback to v1');
    });

    it('deactivates active policy properly', () => {
      const policy = WafPolicy.createDefault('tenant-1', 'site-1');
      expect(policy.isActive).toBe(true);
      policy.deactivate();
      expect(policy.isActive).toBe(false);
    });
  });
});
