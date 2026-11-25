import * as crypto from 'crypto';

/**
 * Pure HMAC-SHA256 signature generator for outbound webhook payloads.
 * Format: sha256=<hex_digest>
 * Uses Node's standard crypto library with ZERO framework dependencies.
 */
export function signWebhookPayload(payload: string, secret: string): string {
  if (!secret) throw new Error('Secret is required for webhook signing');
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(payload, 'utf8');
  return `sha256=${hmac.digest('hex')}`;
}

export function verifyWebhookSignature(
  payload: string,
  secret: string,
  signatureHeader: string,
): boolean {
  if (!signatureHeader || !signatureHeader.startsWith('sha256=')) {
    return false;
  }
  const expectedSignature = signWebhookPayload(payload, secret);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signatureHeader, 'utf8'),
      Buffer.from(expectedSignature, 'utf8'),
    );
  } catch {
    return false;
  }
}
