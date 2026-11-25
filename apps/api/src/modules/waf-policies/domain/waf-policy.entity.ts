import { Entity } from '@shared/domain/entity.base';
import { Result } from '@shared/application/result';
import { PolicyThresholds } from './policy-thresholds.vo';
import { ScopedExclusion } from './scoped-exclusion.vo';

export enum WafMode {
  MONITOR = 'MONITOR',
  BLOCKING = 'BLOCKING',
  STRICT = 'STRICT',
  CORROBORATED = 'CORROBORATED',
  DISABLED = 'DISABLED',
}

export enum MlFailureMode {
  FAIL_OPEN = 'FAIL_OPEN',
  FAIL_CLOSED = 'FAIL_CLOSED',
}

export interface WafPolicyProps {
  tenantId: string;
  siteId: string;
  name: string;
  mode: WafMode;
  mlEnabled: boolean;
  rulesEnabled: boolean;
  challengeEnabled: boolean;
  thresholds: PolicyThresholds;
  mlFailureMode: MlFailureMode;
  exclusions: ScopedExclusion[];
  modelVersion: string;
  version: number;
  isActive: boolean;
  updatedByUserId?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export class WafPolicy extends Entity<string> {
  private _props: WafPolicyProps;

  private constructor(id: string, props: WafPolicyProps) {
    super(id);
    this._props = props;
  }

  get tenantId(): string {
    return this._props.tenantId;
  }

  get siteId(): string {
    return this._props.siteId;
  }

  get name(): string {
    return this._props.name;
  }

  get mode(): WafMode {
    return this._props.mode;
  }

  get mlEnabled(): boolean {
    return this._props.mlEnabled;
  }

  get rulesEnabled(): boolean {
    return this._props.rulesEnabled;
  }

  get challengeEnabled(): boolean {
    return this._props.challengeEnabled;
  }

  get thresholds(): PolicyThresholds {
    return this._props.thresholds;
  }

  get mlFailureMode(): MlFailureMode {
    return this._props.mlFailureMode;
  }

  get exclusions(): ScopedExclusion[] {
    return this._props.exclusions;
  }

  get modelVersion(): string {
    return this._props.modelVersion;
  }

  get version(): number {
    return this._props.version;
  }

  get isActive(): boolean {
    return this._props.isActive;
  }

  get updatedByUserId(): string | null {
    return this._props.updatedByUserId ?? null;
  }

  get createdAt(): Date {
    return this._props.createdAt;
  }

  get updatedAt(): Date {
    return this._props.updatedAt;
  }

  public deactivate(): void {
    this._props.isActive = false;
    this._props.updatedAt = new Date();
  }

  public static createDefault(tenantId: string, siteId: string, updatedByUserId?: string): WafPolicy {
    const thresholds = PolicyThresholds.create(0.05, 0.50, 0.85).getValue();
    const now = new Date();

    return new WafPolicy(crypto.randomUUID(), {
      tenantId,
      siteId,
      name: 'Default Safe Monitor Policy',
      mode: WafMode.MONITOR,
      mlEnabled: true,
      rulesEnabled: true,
      challengeEnabled: true,
      thresholds,
      mlFailureMode: MlFailureMode.FAIL_OPEN,
      exclusions: [],
      modelVersion: 'v1_0',
      version: 1,
      isActive: true,
      updatedByUserId: updatedByUserId ?? null,
      createdAt: now,
      updatedAt: now,
    });
  }

  public createNextVersion(
    updates: {
      mode?: WafMode;
      mlEnabled?: boolean;
      rulesEnabled?: boolean;
      challengeEnabled?: boolean;
      thresholds?: PolicyThresholds;
      mlFailureMode?: MlFailureMode;
      exclusions?: ScopedExclusion[];
      name?: string;
    },
    updatedByUserId?: string,
  ): WafPolicy {
    const now = new Date();

    return new WafPolicy(crypto.randomUUID(), {
      tenantId: this.tenantId,
      siteId: this.siteId,
      name: updates.name ?? this.name,
      mode: updates.mode ?? this.mode,
      mlEnabled: updates.mlEnabled !== undefined ? updates.mlEnabled : this.mlEnabled,
      rulesEnabled: updates.rulesEnabled !== undefined ? updates.rulesEnabled : this.rulesEnabled,
      challengeEnabled: updates.challengeEnabled !== undefined ? updates.challengeEnabled : this.challengeEnabled,
      thresholds: updates.thresholds ?? this.thresholds,
      mlFailureMode: updates.mlFailureMode ?? this.mlFailureMode,
      exclusions: updates.exclusions ?? this.exclusions,
      modelVersion: this.modelVersion,
      version: this.version + 1,
      isActive: true,
      updatedByUserId: updatedByUserId ?? null,
      createdAt: now,
      updatedAt: now,
    });
  }

  public static createRollbackVersion(
    currentActive: WafPolicy,
    targetHistorical: WafPolicy,
    userId?: string,
  ): WafPolicy {
    const now = new Date();

    return new WafPolicy(crypto.randomUUID(), {
      tenantId: currentActive.tenantId,
      siteId: currentActive.siteId,
      name: `Rollback to v${targetHistorical.version}`,
      mode: targetHistorical.mode,
      mlEnabled: targetHistorical.mlEnabled,
      rulesEnabled: targetHistorical.rulesEnabled,
      challengeEnabled: targetHistorical.challengeEnabled,
      thresholds: targetHistorical.thresholds,
      mlFailureMode: targetHistorical.mlFailureMode,
      exclusions: targetHistorical.exclusions,
      modelVersion: targetHistorical.modelVersion,
      version: currentActive.version + 1,
      isActive: true,
      updatedByUserId: userId ?? null,
      createdAt: now,
      updatedAt: now,
    });
  }

  public static reconstitute(id: string, props: WafPolicyProps): WafPolicy {
    return new WafPolicy(id, props);
  }
}
