import { Injectable } from '@nestjs/common';
import {
  IOriginHealthChecker,
  OriginHealthCheckResult,
} from '../../domain/origin-health-checker.interface';

const BLOCKED_HOSTS = new Set([
  '169.254.169.254',
  '0.0.0.0',
  'metadata.google.internal',
  'metadata',
]);

@Injectable()
export class InMemoryOriginHealthChecker implements IOriginHealthChecker {
  private customHealth = new Map<string, OriginHealthCheckResult>();
  private defaultHealthy = true;

  public setDefaultHealthy(healthy: boolean) {
    this.defaultHealthy = healthy;
  }

  public setOriginHealth(originUrl: string, result: OriginHealthCheckResult) {
    this.customHealth.set(originUrl.trim(), result);
  }

  public clear() {
    this.customHealth.clear();
    this.defaultHealthy = true;
  }

  async checkOriginHealth(originUrl: string): Promise<OriginHealthCheckResult> {
    const trimmed = originUrl.trim();

    try {
      const parsed = new URL(trimmed);
      const hostname = parsed.hostname.toLowerCase();

      if (BLOCKED_HOSTS.has(hostname) || hostname.startsWith('169.254.')) {
        return {
          healthy: false,
          latencyMs: 1,
          error: `SSRF Blocked: Host ${hostname} is forbidden for origin health checks.`,
        };
      }
    } catch {
      return {
        healthy: false,
        latencyMs: 1,
        error: `Invalid origin URL format: ${originUrl}`,
      };
    }

    if (this.customHealth.has(trimmed)) {
      return this.customHealth.get(trimmed)!;
    }

    if (trimmed.includes('unhealthy') || trimmed.includes('fail-health') || !this.defaultHealthy) {
      return {
        healthy: false,
        statusCode: 502,
        latencyMs: 25,
        error: 'Simulated origin unreachable (502 Bad Gateway)',
      };
    }

    return {
      healthy: true,
      statusCode: 200,
      latencyMs: 15,
    };
  }
}
