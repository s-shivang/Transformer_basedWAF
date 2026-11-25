import { Entity } from '@shared/domain/entity.base';
import { Result } from '@shared/application/result';
import { SiteDomain } from './site-domain.vo';
import { OriginUrl } from './origin-url.vo';
import * as crypto from 'crypto';

export enum SiteStatus {
  ACTIVE = 'ACTIVE',
  PAUSED = 'PAUSED',
}

export enum OnboardingStatus {
  DRAFT = 'DRAFT',
  PENDING_VERIFICATION = 'PENDING_VERIFICATION',
  VERIFIED = 'VERIFIED',
  CONFIGURING = 'CONFIGURING',
  DNS_PENDING = 'DNS_PENDING',
  TLS_PENDING = 'TLS_PENDING',
  HEALTH_CHECK = 'HEALTH_CHECK',
  ACTIVE = 'ACTIVE',
  FAILED = 'FAILED',
  PAUSED = 'PAUSED',
  REMOVED = 'REMOVED',
}

const VALID_TRANSITIONS: Record<OnboardingStatus, OnboardingStatus[]> = {
  [OnboardingStatus.DRAFT]: [OnboardingStatus.PENDING_VERIFICATION, OnboardingStatus.REMOVED],
  [OnboardingStatus.PENDING_VERIFICATION]: [
    OnboardingStatus.VERIFIED,
    OnboardingStatus.FAILED,
    OnboardingStatus.REMOVED,
  ],
  [OnboardingStatus.VERIFIED]: [
    OnboardingStatus.CONFIGURING,
    OnboardingStatus.FAILED,
    OnboardingStatus.REMOVED,
  ],
  [OnboardingStatus.CONFIGURING]: [OnboardingStatus.DNS_PENDING, OnboardingStatus.FAILED],
  [OnboardingStatus.DNS_PENDING]: [
    OnboardingStatus.TLS_PENDING,
    OnboardingStatus.HEALTH_CHECK,
    OnboardingStatus.FAILED,
  ],
  [OnboardingStatus.TLS_PENDING]: [OnboardingStatus.HEALTH_CHECK, OnboardingStatus.FAILED],
  [OnboardingStatus.HEALTH_CHECK]: [OnboardingStatus.ACTIVE, OnboardingStatus.FAILED],
  [OnboardingStatus.ACTIVE]: [
    OnboardingStatus.PAUSED,
    OnboardingStatus.CONFIGURING,
    OnboardingStatus.REMOVED,
  ],
  [OnboardingStatus.PAUSED]: [OnboardingStatus.ACTIVE, OnboardingStatus.REMOVED],
  [OnboardingStatus.FAILED]: [
    OnboardingStatus.PENDING_VERIFICATION,
    OnboardingStatus.CONFIGURING,
    OnboardingStatus.REMOVED,
  ],
  [OnboardingStatus.REMOVED]: [],
};

export interface ProtectedSiteProps {
  tenantId: string;
  name: string;
  domain: SiteDomain;
  originUrl: OriginUrl;
  status: SiteStatus;
  onboardingStatus: OnboardingStatus;
  verificationToken: string | null;
  verifiedAt: Date | null;
  configVersion: number;
  lastOnboardingError: string | null;
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

  get onboardingStatus(): OnboardingStatus {
    return this._props.onboardingStatus;
  }

  get verificationToken(): string | null {
    return this._props.verificationToken;
  }

  get verifiedAt(): Date | null {
    return this._props.verifiedAt;
  }

  get configVersion(): number {
    return this._props.configVersion;
  }

  get lastOnboardingError(): string | null {
    return this._props.lastOnboardingError;
  }

  get createdAt(): Date {
    return this._props.createdAt;
  }

  get updatedAt(): Date {
    return this._props.updatedAt;
  }

  public transitionTo(newStatus: OnboardingStatus, errorReason?: string): Result<void> {
    const currentStatus = this._props.onboardingStatus;
    const allowed = VALID_TRANSITIONS[currentStatus] || [];

    if (!allowed.includes(newStatus)) {
      return Result.fail<void>(
        `Invalid state transition from ${currentStatus} to ${newStatus}`,
      );
    }

    this._props.onboardingStatus = newStatus;
    this._props.configVersion += 1;
    this._props.updatedAt = new Date();

    if (newStatus === OnboardingStatus.FAILED) {
      this._props.lastOnboardingError = errorReason || 'Onboarding failed';
    } else if (newStatus === OnboardingStatus.VERIFIED) {
      this._props.verifiedAt = new Date();
      this._props.lastOnboardingError = null;
    } else if (newStatus === OnboardingStatus.ACTIVE) {
      this._props.status = SiteStatus.ACTIVE;
      this._props.lastOnboardingError = null;
    } else if (newStatus === OnboardingStatus.PAUSED) {
      this._props.status = SiteStatus.PAUSED;
    }

    return Result.ok<void>();
  }

  public verifyDomain(): Result<void> {
    return this.transitionTo(OnboardingStatus.VERIFIED);
  }

  public failOnboarding(reason: string): Result<void> {
    return this.transitionTo(OnboardingStatus.FAILED, reason);
  }

  public retryOnboarding(
    targetStatus: OnboardingStatus = OnboardingStatus.PENDING_VERIFICATION,
  ): Result<void> {
    if (this._props.onboardingStatus !== OnboardingStatus.FAILED) {
      return Result.fail<void>('Can only retry onboarding from FAILED status');
    }
    return this.transitionTo(targetStatus);
  }

  public pause(): Result<void> {
    return this.transitionTo(OnboardingStatus.PAUSED);
  }

  public resume(): Result<void> {
    return this.transitionTo(OnboardingStatus.ACTIVE);
  }

  public update(props: {
    name?: string;
    originUrl?: OriginUrl;
    status?: SiteStatus;
    onboardingStatus?: OnboardingStatus;
    lastOnboardingError?: string | null;
  }): Result<void> {
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

    if (props.onboardingStatus !== undefined) {
      this._props.onboardingStatus = props.onboardingStatus;
    }

    if (props.lastOnboardingError !== undefined) {
      this._props.lastOnboardingError = props.lastOnboardingError;
    }

    this._props.configVersion += 1;
    this._props.updatedAt = new Date();
    return Result.ok<void>();
  }

  public static generateVerificationToken(): string {
    return `waf-verify-${crypto.randomBytes(16).toString('hex')}`;
  }

  public static create(
    props: {
      tenantId: string;
      name: string;
      domain: SiteDomain;
      originUrl: OriginUrl;
      status?: SiteStatus;
      onboardingStatus?: OnboardingStatus;
      verificationToken?: string | null;
      verifiedAt?: Date | null;
      configVersion?: number;
      lastOnboardingError?: string | null;
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

    const isLegacyDirectActive = props.status === SiteStatus.ACTIVE && !props.onboardingStatus;
    const initialOnboarding = isLegacyDirectActive
      ? OnboardingStatus.ACTIVE
      : props.onboardingStatus ?? OnboardingStatus.PENDING_VERIFICATION;

    const token =
      props.verificationToken !== undefined
        ? props.verificationToken
        : initialOnboarding === OnboardingStatus.ACTIVE
          ? null
          : ProtectedSite.generateVerificationToken();

    const site = new ProtectedSite(siteId, {
      tenantId: props.tenantId,
      name: props.name.trim(),
      domain: props.domain,
      originUrl: props.originUrl,
      status: props.status ?? (initialOnboarding === OnboardingStatus.ACTIVE ? SiteStatus.ACTIVE : SiteStatus.PAUSED),
      onboardingStatus: initialOnboarding,
      verificationToken: token,
      verifiedAt: props.verifiedAt ?? (initialOnboarding === OnboardingStatus.ACTIVE ? now : null),
      configVersion: props.configVersion ?? 1,
      lastOnboardingError: props.lastOnboardingError ?? null,
      createdAt: now,
      updatedAt: now,
    });

    return Result.ok<ProtectedSite>(site);
  }

  public static reconstitute(
    id: string,
    props: {
      tenantId: string;
      name: string;
      domain: SiteDomain;
      originUrl: OriginUrl;
      status: SiteStatus;
      onboardingStatus?: OnboardingStatus;
      verificationToken?: string | null;
      verifiedAt?: Date | null;
      configVersion?: number;
      lastOnboardingError?: string | null;
      createdAt: Date;
      updatedAt: Date;
    },
  ): ProtectedSite {
    return new ProtectedSite(id, {
      tenantId: props.tenantId,
      name: props.name,
      domain: props.domain,
      originUrl: props.originUrl,
      status: props.status,
      onboardingStatus: props.onboardingStatus ?? OnboardingStatus.ACTIVE,
      verificationToken: props.verificationToken ?? null,
      verifiedAt: props.verifiedAt ?? null,
      configVersion: props.configVersion ?? 1,
      lastOnboardingError: props.lastOnboardingError ?? null,
      createdAt: props.createdAt,
      updatedAt: props.updatedAt,
    });
  }
}
