import { Entity } from '@shared/domain/entity.base';
import { Result } from '@shared/application/result';
import { TenantId } from './tenant-id.vo';
import { TenantSlug } from './tenant-slug.vo';

export enum TenantTier {
  FREE = 'FREE',
  PRO = 'PRO',
  ENTERPRISE = 'ENTERPRISE',
}

export enum TenantStatus {
  ACTIVE = 'ACTIVE',
  SUSPENDED = 'SUSPENDED',
  DELETED = 'DELETED',
}

export interface TenantProps {
  name: string;
  slug: TenantSlug;
  tier: TenantTier;
  status: TenantStatus;
  maxSites: number;
  createdAt: Date;
  updatedAt: Date;
}

export class Tenant extends Entity<TenantId> {
  private _props: TenantProps;

  private constructor(id: TenantId, props: TenantProps) {
    super(id);
    this._props = props;
  }

  get name(): string {
    return this._props.name;
  }

  get slug(): TenantSlug {
    return this._props.slug;
  }

  get tier(): TenantTier {
    return this._props.tier;
  }

  get status(): TenantStatus {
    return this._props.status;
  }

  get maxSites(): number {
    return this._props.maxSites;
  }

  get createdAt(): Date {
    return this._props.createdAt;
  }

  get updatedAt(): Date {
    return this._props.updatedAt;
  }

  public updateName(newName: string): Result<void> {
    if (!newName || newName.trim().length === 0) {
      return Result.fail<void>('Tenant name cannot be empty');
    }
    if (newName.trim().length > 100) {
      return Result.fail<void>('Tenant name cannot exceed 100 characters');
    }
    this._props.name = newName.trim();
    this._props.updatedAt = new Date();
    return Result.ok<void>();
  }

  public upgradeTier(newTier: TenantTier): Result<void> {
    this._props.tier = newTier;
    this._props.updatedAt = new Date();
    return Result.ok<void>();
  }

  public updateSiteQuota(newLimit: number): Result<void> {
    if (typeof newLimit !== 'number' || isNaN(newLimit) || newLimit < 1 || newLimit > 100) {
      return Result.fail<void>('Site quota must be an integer between 1 and 100');
    }
    this._props.maxSites = Math.floor(newLimit);
    this._props.updatedAt = new Date();
    return Result.ok<void>();
  }

  public suspend(): Result<void> {
    if (this._props.status === TenantStatus.DELETED) {
      return Result.fail<void>('Cannot suspend a deleted tenant');
    }
    this._props.status = TenantStatus.SUSPENDED;
    this._props.updatedAt = new Date();
    return Result.ok<void>();
  }

  public activate(): Result<void> {
    if (this._props.status === TenantStatus.DELETED) {
      return Result.fail<void>('Cannot activate a deleted tenant');
    }
    this._props.status = TenantStatus.ACTIVE;
    this._props.updatedAt = new Date();
    return Result.ok<void>();
  }

  public delete(): Result<void> {
    this._props.status = TenantStatus.DELETED;
    this._props.updatedAt = new Date();
    return Result.ok<void>();
  }

  public static create(
    props: {
      name: string;
      slug: TenantSlug;
      tier?: TenantTier;
      status?: TenantStatus;
      maxSites?: number;
    },
    id?: TenantId,
  ): Result<Tenant> {
    if (!props.name || props.name.trim().length === 0) {
      return Result.fail<Tenant>('Tenant name cannot be empty');
    }
    if (props.name.trim().length > 100) {
      return Result.fail<Tenant>('Tenant name cannot exceed 100 characters');
    }
    if (!props.slug) {
      return Result.fail<Tenant>('Tenant slug is required');
    }

    const maxSites = props.maxSites ?? 5;
    if (maxSites < 1 || maxSites > 100) {
      return Result.fail<Tenant>('Site quota must be between 1 and 100');
    }

    const tenantId = id ?? TenantId.create(crypto.randomUUID()).getValue();
    const now = new Date();

    const tenant = new Tenant(tenantId, {
      name: props.name.trim(),
      slug: props.slug,
      tier: props.tier ?? TenantTier.FREE,
      status: props.status ?? TenantStatus.ACTIVE,
      maxSites,
      createdAt: now,
      updatedAt: now,
    });

    return Result.ok<Tenant>(tenant);
  }

  public static reconstitute(id: TenantId, props: TenantProps): Tenant {
    return new Tenant(id, {
      ...props,
      maxSites: props.maxSites ?? 5,
    });
  }
}
