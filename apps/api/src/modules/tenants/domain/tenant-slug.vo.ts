import { ValueObject } from '@shared/domain/value-object.base';
import { Result } from '@shared/application/result';

interface TenantSlugProps {
  value: string;
}

export class TenantSlug extends ValueObject<TenantSlugProps> {
  private static readonly SLUG_REGEX = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
  public static readonly MIN_LENGTH = 3;
  public static readonly MAX_LENGTH = 50;

  get value(): string {
    return this.props.value;
  }

  private constructor(props: TenantSlugProps) {
    super(props);
  }

  public static create(rawSlug: string): Result<TenantSlug> {
    if (!rawSlug || typeof rawSlug !== 'string') {
      return Result.fail<TenantSlug>('Tenant slug must be a valid string');
    }

    const trimmed = rawSlug.trim().toLowerCase();

    if (trimmed.length < TenantSlug.MIN_LENGTH) {
      return Result.fail<TenantSlug>(
        `Tenant slug must be at least ${TenantSlug.MIN_LENGTH} characters long`,
      );
    }

    if (trimmed.length > TenantSlug.MAX_LENGTH) {
      return Result.fail<TenantSlug>(
        `Tenant slug must be at most ${TenantSlug.MAX_LENGTH} characters long`,
      );
    }

    if (!TenantSlug.SLUG_REGEX.test(trimmed)) {
      return Result.fail<TenantSlug>(
        'Tenant slug must contain only lowercase alphanumeric characters and hyphens, and cannot start or end with a hyphen',
      );
    }

    return Result.ok<TenantSlug>(new TenantSlug({ value: trimmed }));
  }
}
