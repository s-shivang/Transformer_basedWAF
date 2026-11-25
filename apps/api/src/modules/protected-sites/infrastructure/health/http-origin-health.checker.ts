import { Injectable, Logger } from '@nestjs/common';
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
export class HttpOriginHealthChecker implements IOriginHealthChecker {
  private readonly logger = new Logger(HttpOriginHealthChecker.name);

  async checkOriginHealth(originUrl: string): Promise<OriginHealthCheckResult> {
    const startTime = Date.now();
    try {
      const parsed = new URL(originUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return {
          healthy: false,
          latencyMs: 0,
          error: `Invalid protocol: ${parsed.protocol}. Only http: and https: are allowed.`,
        };
      }

      const hostname = parsed.hostname.toLowerCase();

      // Check SSRF blocked hostnames / IPs
      if (BLOCKED_HOSTS.has(hostname) || hostname.startsWith('169.254.')) {
        return {
          healthy: false,
          latencyMs: 0,
          error: `SSRF Blocked: Host ${hostname} is forbidden for origin health checks.`,
        };
      }

      const allowPrivate = process.env.WAF_ALLOW_PRIVATE_ORIGINS === 'true';
      if (!allowPrivate) {
        if (
          hostname === 'localhost' ||
          hostname === '127.0.0.1' ||
          hostname === '::1' ||
          hostname.startsWith('10.') ||
          hostname.startsWith('192.168.') ||
          /^172\.(1[6-9]|2\d|3[01])\./.test(hostname)
        ) {
          return {
            healthy: false,
            latencyMs: 0,
            error: `SSRF Blocked: Private origin ${hostname} is forbidden in production mode.`,
          };
        }
      }

      // Timeout <= 3 seconds
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      let response: Response;
      try {
        // Try HEAD first
        response = await fetch(originUrl, {
          method: 'HEAD',
          signal: controller.signal,
        });

        // Some servers reject HEAD with 405 Method Not Allowed; fallback to GET
        if (response.status === 405) {
          const getController = new AbortController();
          const getTimeout = setTimeout(() => getController.abort(), 3000);
          try {
            response = await fetch(originUrl, {
              method: 'GET',
              signal: getController.signal,
            });
          } finally {
            clearTimeout(getTimeout);
          }
        }
      } finally {
        clearTimeout(timeoutId);
      }

      const latencyMs = Date.now() - startTime;
      const isHealthy = response.status >= 200 && response.status < 500;

      return {
        healthy: isHealthy,
        statusCode: response.status,
        latencyMs,
        error: isHealthy ? undefined : `Origin returned HTTP error ${response.status}`,
      };
    } catch (err: any) {
      const latencyMs = Date.now() - startTime;
      const errorMsg = err.name === 'AbortError' ? 'Origin health probe timed out after 3000ms' : (err.message || String(err));
      return {
        healthy: false,
        latencyMs,
        error: errorMsg,
      };
    }
  }
}
