import { NotificationSeverity, NotificationType } from './notification-types';

export interface IngestedEventCandidate {
  siteId?: string | null;
  action: string;
  degradedMode?: boolean;
  path?: string;
  requestId?: string;
}

export interface AlertTrigger {
  type: NotificationType;
  severity: NotificationSeverity;
  siteId?: string | null;
  title: string;
  message: string;
  metadata: Record<string, any>;
}

/**
 * Pure domain alert trigger evaluation function.
 * ZERO framework or database dependencies.
 *
 * Checks:
 * 1. ATTACK_SPIKE: >= 5 BLOCK events for the same site in a batch
 * 2. ML_DEGRADED: any event ingested with degradedMode === true
 */
export function evaluateAlertTriggers(
  events: IngestedEventCandidate[],
  options?: { attackSpikeThreshold?: number },
): AlertTrigger[] {
  if (!events || events.length === 0) return [];

  const triggers: AlertTrigger[] = [];
  const spikeThreshold = options?.attackSpikeThreshold || 5;

  // 1. Group BLOCK events by siteId
  const blockCountBySite = new Map<string, number>();
  let degradedDetected = false;
  let degradedEvent: IngestedEventCandidate | null = null;

  for (const event of events) {
    if (event.action === 'BLOCK') {
      const siteKey = event.siteId || 'unassigned';
      blockCountBySite.set(siteKey, (blockCountBySite.get(siteKey) || 0) + 1);
    }

    if (event.degradedMode && !degradedDetected) {
      degradedDetected = true;
      degradedEvent = event;
    }
  }

  // Check Attack Spikes (>= 5 blocks for same site)
  blockCountBySite.forEach((count, siteKey) => {
    if (count >= spikeThreshold) {
      const resolvedSiteId = siteKey === 'unassigned' ? null : siteKey;
      triggers.push({
        type: 'ATTACK_SPIKE',
        severity: 'CRITICAL',
        siteId: resolvedSiteId,
        title: 'High Attack Volume Detected',
        message: `Detected attack surge: ${count} requests were blocked within the current telemetry batch.`,
        metadata: {
          blockedCount: count,
          siteId: resolvedSiteId,
          threshold: spikeThreshold,
        },
      });
    }
  });

  // Check ML Degradation
  if (degradedDetected && degradedEvent) {
    triggers.push({
      type: 'ML_DEGRADED',
      severity: 'WARNING',
      siteId: degradedEvent.siteId || null,
      title: 'ML Inference Service Operating in Degraded Mode',
      message:
        'The WAF data plane reported inference timeout or model unavailability; fail-safe mode was activated.',
      metadata: {
        siteId: degradedEvent.siteId || null,
        requestId: degradedEvent.requestId || null,
      },
    });
  }

  return triggers;
}
