/**
 * Pure domain utility for defensive scrubbing of sensitive credentials,
 * tokens, session cookies, and authentication headers.
 */
const SENSITIVE_KEY_PATTERNS = [
  /authorization/i,
  /^cookie$/i,
  /^set-cookie$/i,
  /password/i,
  /secret/i,
  /api[_-]?key/i,
  /token/i,
  /private[_-]?key/i,
];

export function sanitizeRedactedPayload(input: any): any {
  if (input === null || input === undefined) {
    return input;
  }

  if (typeof input === 'string') {
    // Redact common bearer tokens or password patterns in raw text if present
    return input
      .replace(/Bearer\s+[A-Za-z0-9\-_.]+/gi, 'Bearer [REDACTED]')
      .replace(/(password|passwd|pwd)\s*=\s*[^&\s]+/gi, '$1=[REDACTED]');
  }

  if (Array.isArray(input)) {
    return input.map((item) => sanitizeRedactedPayload(item));
  }

  if (typeof input === 'object') {
    const sanitized: Record<string, any> = {};
    for (const [key, value] of Object.entries(input)) {
      const isSensitive = SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(key));
      if (isSensitive) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = sanitizeRedactedPayload(value);
      }
    }
    return sanitized;
  }

  return input;
}
