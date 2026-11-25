import { Entity } from '@shared/domain/entity.base';
import { Result } from '@shared/application/result';

export interface RefreshSessionProps {
  userId: string;
  tenantId: string;
  tokenHash: string;
  expiresAt: Date;
  revokedAt?: Date | null;
  createdAt: Date;
}

export class RefreshSession extends Entity<string> {
  private _props: RefreshSessionProps;

  private constructor(id: string, props: RefreshSessionProps) {
    super(id);
    this._props = props;
  }

  get userId(): string {
    return this._props.userId;
  }

  get tenantId(): string {
    return this._props.tenantId;
  }

  get tokenHash(): string {
    return this._props.tokenHash;
  }

  get expiresAt(): Date {
    return this._props.expiresAt;
  }

  get revokedAt(): Date | null {
    return this._props.revokedAt ?? null;
  }

  get createdAt(): Date {
    return this._props.createdAt;
  }

  get isRevoked(): boolean {
    return this._props.revokedAt !== null && this._props.revokedAt !== undefined;
  }

  get isExpired(): boolean {
    return new Date() > this._props.expiresAt;
  }

  public revoke(): void {
    this._props.revokedAt = new Date();
  }

  public static create(
    props: {
      userId: string;
      tenantId: string;
      tokenHash: string;
      expiresAt: Date;
    },
    id?: string,
  ): Result<RefreshSession> {
    if (!props.userId) return Result.fail<RefreshSession>('userId is required');
    if (!props.tenantId) return Result.fail<RefreshSession>('tenantId is required');
    if (!props.tokenHash) return Result.fail<RefreshSession>('tokenHash is required');
    if (!props.expiresAt) return Result.fail<RefreshSession>('expiresAt is required');

    const sessionId = id ?? crypto.randomUUID();
    const session = new RefreshSession(sessionId, {
      userId: props.userId,
      tenantId: props.tenantId,
      tokenHash: props.tokenHash,
      expiresAt: props.expiresAt,
      revokedAt: null,
      createdAt: new Date(),
    });

    return Result.ok<RefreshSession>(session);
  }

  public static reconstitute(id: string, props: RefreshSessionProps): RefreshSession {
    return new RefreshSession(id, props);
  }
}
