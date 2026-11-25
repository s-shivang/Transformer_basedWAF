import { Entity } from '@shared/domain/entity.base';
import { Result } from '@shared/application/result';
import { WafAction, SecuritySeverity } from './security-event.types';
import { sanitizeRedactedPayload } from './sanitize-payload';

export interface SecurityEventProps {
  tenantId: string;
  siteId?: string | null;
  requestId: string;
  clientIpHash?: string | null;
  method: string;
  path: string;
  action: WafAction;
  wouldAction?: WafAction | null;
  reason?: string | null;
  riskScore: number;
  severity: SecuritySeverity;
  stageUsed?: string | null;
  ruleMatches: any[];
  anomalyFlags: any[];
  degradedMode: boolean;
  modelVersion: string;
  policyVersion: number;
  latencyMs: number;
  redactedRequest?: any | null;
  createdAt: Date;
}

export class SecurityEvent extends Entity<string> {
  private _props: SecurityEventProps;

  private constructor(id: string, props: SecurityEventProps) {
    super(id);
    this._props = props;
  }

  get tenantId(): string {
    return this._props.tenantId;
  }

  get siteId(): string | null {
    return this._props.siteId ?? null;
  }

  get requestId(): string {
    return this._props.requestId;
  }

  get clientIpHash(): string | null {
    return this._props.clientIpHash ?? null;
  }

  get method(): string {
    return this._props.method;
  }

  get path(): string {
    return this._props.path;
  }

  get action(): WafAction {
    return this._props.action;
  }

  get wouldAction(): WafAction | null {
    return this._props.wouldAction ?? null;
  }

  get reason(): string | null {
    return this._props.reason ?? null;
  }

  get riskScore(): number {
    return this._props.riskScore;
  }

  get severity(): SecuritySeverity {
    return this._props.severity;
  }

  get stageUsed(): string | null {
    return this._props.stageUsed ?? null;
  }

  get ruleMatches(): any[] {
    return this._props.ruleMatches;
  }

  get anomalyFlags(): any[] {
    return this._props.anomalyFlags;
  }

  get degradedMode(): boolean {
    return this._props.degradedMode;
  }

  get modelVersion(): string {
    return this._props.modelVersion;
  }

  get policyVersion(): number {
    return this._props.policyVersion;
  }

  get latencyMs(): number {
    return this._props.latencyMs;
  }

  get redactedRequest(): any | null {
    return this._props.redactedRequest ?? null;
  }

  get createdAt(): Date {
    return this._props.createdAt;
  }

  public static create(props: {
    id?: string;
    tenantId: string;
    siteId?: string | null;
    requestId: string;
    clientIpHash?: string | null;
    method: string;
    path: string;
    action: WafAction;
    wouldAction?: WafAction | null;
    reason?: string | null;
    riskScore?: number;
    severity?: SecuritySeverity;
    stageUsed?: string | null;
    ruleMatches?: any[];
    anomalyFlags?: any[];
    degradedMode?: boolean;
    modelVersion?: string;
    policyVersion?: number;
    latencyMs?: number;
    redactedRequest?: any | null;
    createdAt?: Date;
  }): Result<SecurityEvent> {
    if (!props.tenantId || typeof props.tenantId !== 'string') {
      return Result.fail<SecurityEvent>('tenantId is required');
    }

    if (!props.requestId || typeof props.requestId !== 'string') {
      return Result.fail<SecurityEvent>('requestId is required');
    }

    if (!props.method || typeof props.method !== 'string') {
      return Result.fail<SecurityEvent>('HTTP method is required');
    }

    if (!props.path || typeof props.path !== 'string') {
      return Result.fail<SecurityEvent>('path is required');
    }

    if (!props.action || !Object.values(WafAction).includes(props.action)) {
      return Result.fail<SecurityEvent>('Valid WAF action is required');
    }

    const score = props.riskScore !== undefined ? Math.max(0.0, Math.min(1.0, props.riskScore)) : 0.0;

    let computedSeverity = props.severity ?? SecuritySeverity.LOW;
    if (!props.severity) {
      if (score >= 0.85 || props.action === WafAction.BLOCK) {
        computedSeverity = SecuritySeverity.HIGH;
      } else if (score >= 0.50 || props.action === WafAction.CHALLENGE) {
        computedSeverity = SecuritySeverity.MEDIUM;
      } else if (score >= 0.05) {
        computedSeverity = SecuritySeverity.LOW;
      }
    }

    // Apply domain redaction guard to ensure sensitive credentials are stripped
    const safeRedacted = props.redactedRequest ? sanitizeRedactedPayload(props.redactedRequest) : null;

    return Result.ok<SecurityEvent>(
      new SecurityEvent(props.id ?? crypto.randomUUID(), {
        tenantId: props.tenantId,
        siteId: props.siteId ?? null,
        requestId: props.requestId.trim(),
        clientIpHash: props.clientIpHash ?? null,
        method: props.method.trim().toUpperCase(),
        path: props.path.trim(),
        action: props.action,
        wouldAction: props.wouldAction ?? null,
        reason: props.reason?.trim() ?? null,
        riskScore: Math.round(score * 10000) / 10000,
        severity: computedSeverity,
        stageUsed: props.stageUsed?.trim() ?? null,
        ruleMatches: Array.isArray(props.ruleMatches) ? props.ruleMatches : [],
        anomalyFlags: Array.isArray(props.anomalyFlags) ? props.anomalyFlags : [],
        degradedMode: props.degradedMode ?? false,
        modelVersion: props.modelVersion ?? 'v1_0',
        policyVersion: props.policyVersion ?? 1,
        latencyMs: props.latencyMs !== undefined ? Math.max(0, props.latencyMs) : 0,
        redactedRequest: safeRedacted,
        createdAt: props.createdAt ?? new Date(),
      }),
    );
  }

  public static reconstitute(id: string, props: SecurityEventProps): SecurityEvent {
    return new SecurityEvent(id, props);
  }
}
