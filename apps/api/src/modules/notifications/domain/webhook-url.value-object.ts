import { ValueObject } from '@shared/domain/value-object.base';

export class WebhookUrl extends ValueObject<{ url: string }> {
  private constructor(props: { url: string }) {
    super(props);
  }

  public static create(rawUrl: string): WebhookUrl {
    if (!rawUrl || typeof rawUrl !== 'string') {
      throw new Error('Webhook URL must be a non-empty string');
    }

    const trimmed = rawUrl.trim();

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(trimmed);
    } catch (e) {
      throw new Error(`Invalid Webhook URL format: ${trimmed}`);
    }

    const protocol = parsedUrl.protocol.toLowerCase();
    const hostname = parsedUrl.hostname.toLowerCase();

    // Enforce protocol: https or local development http://localhost / http://127.0.0.1
    const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
    if (protocol !== 'https:' && !(protocol === 'http:' && isLocalhost)) {
      throw new Error(
        `Webhook URL must use HTTPS (HTTP is strictly permitted only for localhost testing). Received: ${protocol}`,
      );
    }

    // SSRF Protections:
    // Strictly block cloud metadata IP (AWS/GCP/Azure link-local: 169.254.x.x, 0.0.0.0, internal cloud DNS)
    if (
      hostname === '169.254.169.254' ||
      hostname.startsWith('169.254.') ||
      hostname === '0.0.0.0' ||
      hostname === 'metadata.google.internal' ||
      hostname === 'instance-data'
    ) {
      throw new Error(
        `SSRF Protection Violation: Webhook destination '${hostname}' targets restricted link-local or cloud metadata service.`,
      );
    }

    return new WebhookUrl({ url: trimmed });
  }

  get value(): string {
    return this.props.url;
  }
}
