import { SecurityEvent } from '../../security-events/domain/security-event.entity';
import { WafAction } from '../../security-events/domain/security-event.types';
import {
  computePercentile,
  computeOverviewMetrics,
  computeTimeseriesBuckets,
  computeTopThreats,
} from './analytics-calculator';

describe('Analytics Pure Domain Calculations', () => {
  describe('computePercentile', () => {
    it('computes p50 and p95 correctly on sorted numbers', () => {
      const latencies = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      expect(computePercentile(latencies, 50)).toBe(5);
      expect(computePercentile(latencies, 95)).toBe(10);
    });

    it('handles empty arrays gracefully', () => {
      expect(computePercentile([], 50)).toBe(0);
    });
  });

  describe('computeOverviewMetrics', () => {
    it('aggregates counts, block rate, and latencies from events', () => {
      const events = [
        SecurityEvent.create({
          tenantId: 't1',
          requestId: 'r1',
          method: 'GET',
          path: '/api',
          action: WafAction.ALLOW,
          latencyMs: 2.0,
        }).getValue(),
        SecurityEvent.create({
          tenantId: 't1',
          requestId: 'r2',
          method: 'POST',
          path: '/login',
          action: WafAction.BLOCK,
          riskScore: 0.90,
          latencyMs: 10.0,
        }).getValue(),
        SecurityEvent.create({
          tenantId: 't1',
          requestId: 'r3',
          method: 'POST',
          path: '/search',
          action: WafAction.CHALLENGE,
          riskScore: 0.65,
          latencyMs: 5.0,
        }).getValue(),
        SecurityEvent.create({
          tenantId: 't1',
          requestId: 'r4',
          method: 'GET',
          path: '/test',
          action: WafAction.MONITOR,
          latencyMs: 3.0,
          degradedMode: true,
        }).getValue(),
      ];

      const metrics = computeOverviewMetrics(events, 2);

      expect(metrics.totalRequests).toBe(4);
      expect(metrics.allowedCount).toBe(1);
      expect(metrics.blockedCount).toBe(1);
      expect(metrics.challengedCount).toBe(1);
      expect(metrics.monitoredCount).toBe(1);
      expect(metrics.degradedCount).toBe(1);
      expect(metrics.blockRatePct).toBe(25.0); // 1 out of 4 = 25%
      expect(metrics.pendingFalsePositivesCount).toBe(2);
      expect(metrics.avgLatencyMs).toBe(5.0); // (2+10+5+3)/4 = 5.0
    });

    it('returns clean zeroed metrics for empty event list', () => {
      const metrics = computeOverviewMetrics([], 0);
      expect(metrics.totalRequests).toBe(0);
      expect(metrics.blockRatePct).toBe(0.0);
      expect(metrics.avgLatencyMs).toBe(0.0);
    });
  });

  describe('computeTimeseriesBuckets', () => {
    it('buckets events into hourly buckets for 24h window', () => {
      const d1 = new Date('2026-11-25T10:15:00Z');
      const d2 = new Date('2026-11-25T10:45:00Z');
      const d3 = new Date('2026-11-25T11:05:00Z');

      const events = [
        SecurityEvent.create({
          tenantId: 't1',
          requestId: 'r1',
          method: 'GET',
          path: '/api',
          action: WafAction.ALLOW,
          createdAt: d1,
        }).getValue(),
        SecurityEvent.create({
          tenantId: 't1',
          requestId: 'r2',
          method: 'POST',
          path: '/login',
          action: WafAction.BLOCK,
          createdAt: d2,
        }).getValue(),
        SecurityEvent.create({
          tenantId: 't1',
          requestId: 'r3',
          method: 'GET',
          path: '/about',
          action: WafAction.ALLOW,
          createdAt: d3,
        }).getValue(),
      ];

      const buckets = computeTimeseriesBuckets(events, '24h');
      expect(buckets.length).toBe(2);

      expect(buckets[0].bucket).toBe('2026-11-25T10:00:00Z');
      expect(buckets[0].total).toBe(2);
      expect(buckets[0].blocked).toBe(1);
      expect(buckets[0].allowed).toBe(1);

      expect(buckets[1].bucket).toBe('2026-11-25T11:00:00Z');
      expect(buckets[1].total).toBe(1);
    });
  });

  describe('computeTopThreats', () => {
    it('ranks top attacked paths and top trigger reasons', () => {
      const events = [
        SecurityEvent.create({
          tenantId: 't1',
          requestId: 'r1',
          method: 'POST',
          path: '/api/v1/auth',
          action: WafAction.BLOCK,
          riskScore: 0.95,
          reason: 'SQLi attempt in username',
        }).getValue(),
        SecurityEvent.create({
          tenantId: 't1',
          requestId: 'r2',
          method: 'POST',
          path: '/api/v1/auth',
          action: WafAction.BLOCK,
          riskScore: 0.98,
          reason: 'SQLi attempt in username',
        }).getValue(),
        SecurityEvent.create({
          tenantId: 't1',
          requestId: 'r3',
          method: 'GET',
          path: '/search',
          action: WafAction.CHALLENGE,
          riskScore: 0.70,
          reason: 'Unusual query pattern',
        }).getValue(),
      ];

      const { topPaths, topReasons } = computeTopThreats(events, 5);

      expect(topPaths.length).toBe(2);
      expect(topPaths[0].path).toBe('/api/v1/auth');
      expect(topPaths[0].count).toBe(2);
      expect(topPaths[0].blockedCount).toBe(2);
      expect(topPaths[0].maxRiskScore).toBe(0.98);

      expect(topReasons.length).toBe(2);
      expect(topReasons[0].reason).toBe('SQLi attempt in username');
      expect(topReasons[0].count).toBe(2);
      expect(topReasons[0].percentage).toBe(66.67);
    });
  });
});
