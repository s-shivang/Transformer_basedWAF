import { ValueObject } from '@shared/domain/value-object.base';
import { Result } from '@shared/application/result';

interface SiteDomainProps {
  value: string;
}

export class SiteDomain extends ValueObject<SiteDomainProps> {
  private static readonly DOMAIN_REGEX =
    /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^localhost$/;

  get value(): string {
    return this.props.value;
  }

  private constructor(props: SiteDomainProps) {
    super(props);
  }

  public static create(rawDomain: string): Result<SiteDomain> {
    if (!rawDomain || typeof rawDomain !== 'string') {
      return Result.fail<SiteDomain>('Domain must be a valid string');
    }

    let normalized = rawDomain.trim().toLowerCase();

    // Reject schemes or path traversal
    if (normalized.includes('://') || normalized.includes('/') || normalized.includes(':')) {
      return Result.fail<SiteDomain>('Domain must not include URL scheme, path, or port');
    }

    // Reject wildcards
    if (normalized.includes('*')) {
      return Result.fail<SiteDomain>('Wildcard domains are not permitted');
    }

    if (!SiteDomain.DOMAIN_REGEX.test(normalized)) {
      return Result.fail<SiteDomain>('Invalid domain format (e.g. app.example.com)');
    }

    return Result.ok<SiteDomain>(new SiteDomain({ value: normalized }));
  }
}
