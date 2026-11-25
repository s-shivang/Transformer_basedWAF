import { Entity } from '@shared/domain/entity.base';
import { Result } from '@shared/application/result';
import { Email } from './email.vo';

export interface UserProps {
  email: Email;
  passwordHash: string;
  name?: string | null;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export class User extends Entity<string> {
  private _props: UserProps;

  private constructor(id: string, props: UserProps) {
    super(id);
    this._props = props;
  }

  get email(): Email {
    return this._props.email;
  }

  get passwordHash(): string {
    return this._props.passwordHash;
  }

  get name(): string | null {
    return this._props.name ?? null;
  }

  get isActive(): boolean {
    return this._props.isActive;
  }

  get createdAt(): Date {
    return this._props.createdAt;
  }

  get updatedAt(): Date {
    return this._props.updatedAt;
  }

  public updatePassword(newPasswordHash: string): Result<void> {
    if (!newPasswordHash || newPasswordHash.trim().length === 0) {
      return Result.fail<void>('Password hash cannot be empty');
    }
    this._props.passwordHash = newPasswordHash;
    this._props.updatedAt = new Date();
    return Result.ok<void>();
  }

  public deactivate(): void {
    this._props.isActive = false;
    this._props.updatedAt = new Date();
  }

  public activate(): void {
    this._props.isActive = true;
    this._props.updatedAt = new Date();
  }

  public static create(
    props: {
      email: Email;
      passwordHash: string;
      name?: string | null;
      isActive?: boolean;
    },
    id?: string,
  ): Result<User> {
    if (!props.email) {
      return Result.fail<User>('User email is required');
    }
    if (!props.passwordHash || props.passwordHash.trim().length === 0) {
      return Result.fail<User>('Password hash is required');
    }

    const userId = id ?? crypto.randomUUID();
    const now = new Date();

    const user = new User(userId, {
      email: props.email,
      passwordHash: props.passwordHash,
      name: props.name ?? null,
      isActive: props.isActive ?? true,
      createdAt: now,
      updatedAt: now,
    });

    return Result.ok<User>(user);
  }

  public static reconstitute(id: string, props: UserProps): User {
    return new User(id, props);
  }
}
