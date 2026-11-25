import { SecurityEvent } from '../../security-events/domain/security-event.entity';
import { WafAction } from '../../security-events/domain/security-event.types';

export interface OverviewMetrics {
  totalRequests: number;
  blockedCount: number;
  challengedCount: number;
  monitoredCount: number;
  allowedCount: number;
  blockRatePct: number;
  degradedCount: number;
  avgLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  pendingFalsePositivesCount: number;
}

export interface TimeseriesBucket {
  bucket: string;
  total: number;
  blocked: number;
  challenged: number;
  monitored: number;
  allowed: number;
}

export interface TopAttackedPath {
  path: string;
  count: number;
  blockedCount: number;
  maxRiskScore: number;
}

export interface TopTriggerReason {
  reason: string;
  count: number;
  percentage: number;
}

export interface TopThreatsResult {
  topPaths: TopAttackedPath[];
  topReasons: TopTriggerReason[];
}

export function computePercentile(numbers: number[], percentile: number): number {
  if (numbers.length === 0) return 0;
  const sorted = [...numbers].sort((a, b) => a - b);
  const index = Math.ceil((percentile / 100) * sorted.length) - 1;
  const clampedIndex = Math.max(0, Math.min(sorted.length - 1, index));
  return Math.round(sorted[clampedIndex] * 100) / 100;
}

export function computeOverviewMetrics(
  events: SecurityEvent[],
  pendingFalsePositivesCount: number = 0,
): OverviewMetrics {
  const total = events.length;
  if (total === 0) {
    return {
      totalRequests: 0,
      blockedCount: 0,
      challengedCount: 0,
      monitoredCount: 0,
      allowedCount: 0,
      blockRatePct: 0.0,
      degradedCount: 0,
      avgLatencyMs: 0.0,
      p50LatencyMs: 0.0,
      p95LatencyMs: 0.0,
      pendingFalsePositivesCount,
    };
  }

  let blocked = 0;
  let challenged = 0;
  let monitored = 0;
  let allowed = 0;
  let degraded = 0;
  let latencySum = 0;
  const latencies: number[] = [];

  for (const e of events) {
    if (e.action === WafAction.BLOCK) blocked++;
    else if (e.action === WafAction.CHALLENGE) challenged++;
    else if (e.action === WafAction.MONITOR) monitored++;
    else if (e.action === WafAction.ALLOW) allowed++;

    if (e.degradedMode) degraded++;
    latencySum += e.latencyMs;
    latencies.push(e.latencyMs);
  }

  const avgLatency = Math.round((latencySum / total) * 100) / 100;
  const blockRate = Math.round((blocked / total) * 10000) / 100; // e.g. 15.25%

  return {
    totalRequests: total,
    blockedCount: blocked,
    challengedCount: challenged,
    monitoredCount: monitored,
    allowedCount: allowed,
    blockRatePct: blockRate,
    degradedCount: degraded,
    avgLatencyMs: avgLatency,
    p50LatencyMs: computePercentile(latencies, 50),
    p95LatencyMs: computePercentile(latencies, 95),
    pendingFalsePositivesCount,
  };
}

export function computeTimeseriesBuckets(
  events: SecurityEvent[],
  window: '24h' | '7d' | '30d' = '24h',
): TimeseriesBucket[] {
  const bucketMap: Map<string, { total: number; blocked: number; challenged: number; monitored: number; allowed: number }> =
    new Map();

  for (const e of events) {
    let key: string;
    const d = e.createdAt;
    if (window === '24h') {
      // Hourly bucket: YYYY-MM-DDTHH:00:00Z
      const yyyy = d.getUTCFullYear();
      const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
      const dd = String(d.getUTCDate()).padStart(2, '0');
      const hh = String(d.getUTCHours()).padStart(2, '0');
      key = `${yyyy}-${mm}-${dd}T${hh}:00:00Z`;
    } else {
      // Daily bucket: YYYY-MM-DD
      const yyyy = d.getUTCFullYear();
      const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
      const dd = String(d.getUTCDate()).padStart(2, '0');
      key = `${yyyy}-${mm}-${dd}`;
    }

    if (!bucketMap.has(key)) {
      bucketMap.set(key, { total: 0, blocked: 0, challenged: 0, monitored: 0, allowed: 0 });
    }

    const b = bucketMap.get(key)!;
    b.total++;
    if (e.action === WafAction.BLOCK) b.blocked++;
    else if (e.action === WafAction.CHALLENGE) b.challenged++;
    else if (e.action === WafAction.MONITOR) b.monitored++;
    else if (e.action === WafAction.ALLOW) b.allowed++;
  }

  // Sort buckets chronologically
  const sortedKeys = Array.from(bucketMap.keys()).sort();
  return sortedKeys.map((k) => ({
    bucket: k,
    ...bucketMap.get(k)!,
  }));
}

export function computeTopThreats(
  events: SecurityEvent[],
  limit: number = 10,
): TopThreatsResult {
  const pathMap: Map<string, { count: number; blocked: number; maxScore: number }> = new Map();
  const reasonMap: Map<string, number> = new Map();

  for (const e of events) {
    // Tally paths
    const p = e.path;
    if (!pathMap.has(p)) {
      pathMap.set(p, { count: 0, blocked: 0, maxScore: 0 });
    }
    const pEntry = pathMap.get(p)!;
    pEntry.count++;
    if (e.action === WafAction.BLOCK) pEntry.blocked++;
    if (e.riskScore > pEntry.maxScore) pEntry.maxScore = e.riskScore;

    // Tally trigger reasons
    if (e.reason) {
      const r = e.reason.trim();
      reasonMap.set(r, (reasonMap.get(r) ?? 0) + 1);
    }
  }

  // Top paths sorted by count desc
  const topPaths: TopAttackedPath[] = Array.from(pathMap.entries())
    .map(([path, data]) => ({
      path,
      count: data.count,
      blockedCount: data.blocked,
      maxRiskScore: Math.round(data.maxScore * 10000) / 10000,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);

  // Top reasons sorted by count desc
  const totalReasonsCount = Array.from(reasonMap.values()).reduce((sum, v) => sum + v, 0);
  const topReasons: TopTriggerReason[] = Array.from(reasonMap.entries())
    .map(([reason, count]) => ({
      reason,
      count,
      percentage: totalReasonsCount > 0 ? Math.round((count / totalReasonsCount) * 10000) / 100 : 0,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);

  return { topPaths, topReasons };
}
