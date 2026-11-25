export const ORIGIN_HEALTH_CHECKER = Symbol('ORIGIN_HEALTH_CHECKER');

export interface OriginHealthCheckResult {
  healthy: boolean;
  statusCode?: number;
  latencyMs: number;
  error?: string;
}

export interface IOriginHealthChecker {
  checkOriginHealth(originUrl: string): Promise<OriginHealthCheckResult>;
}
