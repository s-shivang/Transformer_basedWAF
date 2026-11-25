import { Entity } from '@shared/domain/entity.base';
import { Result } from '@shared/application/result';
import { SiteDomain } from './site-domain.vo';
import { OriginUrl } from './origin-url.vo';

export enum SiteStatus {
  ACTIVE = 'ACTIVE',
  PAUSED = 'PAUSED',
}

export interface ProtectedSiteProps {
  tenantId: string;
  name: string;
  domain: SiteDomain;
  originUrl: OriginUrl;
  status: SiteStatus;
  createdAt: Date;
  updatedAt: Date;
}

export class ProtectedSite extends Entity<string> {
  private _props: ProtectedSiteProps;

  private constructor(id: string, props: ProtectedSiteProps) {
    super(id);
    this._props = props;
  }

  get tenantId(): string {
    return this._props.tenantId;
  }

  get name(): string {
    return this._props.name;
  }

  get domain(): SiteDomain {
    return this._props.domain;
  }

  get originUrl(): OriginUrl {
    return this._props.originUrl;
  }

  get status(): SiteStatus {
    return this._props.status;
  }

  get createdAt(): Date {
    return this._props.createdAt;
  }

  get updatedAt(): Date {
    return this._props.updatedAt;
  }

  public update(props: { name?: string; originUrl?: OriginUrl; status?: SiteStatus }): Result<void> {
    if (props.name !== undefined) {
      if (!props.name || props.name.trim().length === 0) {
        return Result.fail<void>('Site name cannot be empty');
      }
      this._props.name = props.name.trim();
    }

    if (props.originUrl !== undefined) {
      this._props.originUrl = props.originUrl;
    }

    if (props.status !== undefined) {
      this._props.status = props.status;
    }

    this._props.updatedAt = new Date();
    return Result.ok<void>();
  }

  public static create(
    props: {
      tenantId: string;
      name: string;
      domain: SiteDomain;
      originUrl: OriginUrl;
      status?: SiteStatus;
    },
    id?: string,
  ): Result<ProtectedSite> {
    if (!props.tenantId) return Result.fail<ProtectedSite>('tenantId is required');
    if (!props.name || props.name.trim().length === 0) {
      return Result.fail<ProtectedSite>('Site name cannot be empty');
    }
    if (!props.domain) return Result.fail<ProtectedSite>('Domain is required');
    if (!props.originUrl) return Result.fail<ProtectedSite>('Origin URL is required');

    const siteId = id ?? crypto.randomUUID();
    const now = new Date();

    const site = new ProtectedSite(siteId, {
      tenantId: props.tenantId,
      name: props.name.trim(),
      domain: props.domain,
      originUrl: props.originUrl,
      status: props.status ?? SiteStatus.ACTIVE,
      createdAt: now,
      updatedAt: now,
    });

    return Result.ok<ProtectedSite>(site);
  }

  public static reconstitute(id: string, props: ProtectedSiteProps): ProtectedSite {
    return new ProtectedSite(id, props);
  }
}
