import { ValueObject } from '@shared/domain/value-object.base';
import { Result } from '@shared/application/result';

interface OriginUrlProps {
  value: string;
}

export class OriginUrl extends ValueObject<OriginUrlProps> {
  private static readonly BLOCKED_HOSTS = [
    '169.254.169.254', // AWS / GCP / Azure Instance Metadata
    'metadata.google.internal',
    '100.100.100.200', // Alibaba Cloud Metadata
    '0.0.0.0',
  ];

  get value(): string {
    return this.props.value;
  }

  private constructor(props: OriginUrlProps) {
    super(props);
  }

  public static create(rawUrl: string): Result<OriginUrl> {
    if (!rawUrl || typeof rawUrl !== 'string') {
      return Result.fail<OriginUrl>('Origin URL must be a valid string');
    }

    const trimmed = rawUrl.trim();

    try {
      const parsed = new URL(trimmed);

      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return Result.fail<OriginUrl>('Origin URL must use http:// or https:// scheme');
      }

      const hostname = parsed.hostname.toLowerCase();

      // Check SSRF blocked hosts
      for (const blocked of OriginUrl.BLOCKED_HOSTS) {
        if (hostname === blocked) {
          return Result.fail<OriginUrl>(`Forbidden origin host: ${hostname} (SSRF protection)`);
        }
      }

      return Result.ok<OriginUrl>(new OriginUrl({ value: trimmed }));
    } catch {
      return Result.fail<OriginUrl>('Invalid origin URL format');
    }
  }
}
