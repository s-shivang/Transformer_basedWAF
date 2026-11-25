import { Entity } from '@shared/domain/entity.base';
import { Result } from '@shared/application/result';
import { UserRole } from './user-role';

export interface MembershipProps {
  tenantId: string;
  userId: string;
  role: UserRole;
  createdAt: Date;
  updatedAt: Date;
}

export class Membership extends Entity<string> {
  private _props: MembershipProps;

  private constructor(id: string, props: MembershipProps) {
    super(id);
    this._props = props;
  }

  get tenantId(): string {
    return this._props.tenantId;
  }

  get userId(): string {
    return this._props.userId;
  }

  get role(): UserRole {
    return this._props.role;
  }

  get createdAt(): Date {
    return this._props.createdAt;
  }

  get updatedAt(): Date {
    return this._props.updatedAt;
  }

  public changeRole(newRole: UserRole): Result<void> {
    this._props.role = newRole;
    this._props.updatedAt = new Date();
    return Result.ok<void>();
  }

  public static create(
    props: {
      tenantId: string;
      userId: string;
      role?: UserRole;
    },
    id?: string,
  ): Result<Membership> {
    if (!props.tenantId) {
      return Result.fail<Membership>('Tenant ID is required for membership');
    }
    if (!props.userId) {
      return Result.fail<Membership>('User ID is required for membership');
    }

    const membershipId = id ?? crypto.randomUUID();
    const now = new Date();

    const membership = new Membership(membershipId, {
      tenantId: props.tenantId,
      userId: props.userId,
      role: props.role ?? UserRole.VIEWER,
      createdAt: now,
      updatedAt: now,
    });

    return Result.ok<Membership>(membership);
  }

  public static reconstitute(id: string, props: MembershipProps): Membership {
    return new Membership(id, props);
  }
}
