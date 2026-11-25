import { WebhookUrl } from './webhook-url.value-object';
import { signWebhookPayload, verifyWebhookSignature } from './webhook-signature';
import { Notification } from './notification.entity';
import { evaluateAlertTriggers } from './alert-evaluator';

describe('Notifications & Webhook Domain Invariants', () => {
  describe('WebhookUrl SSRF Protection & Protocol Validation', () => {
    it('accepts valid HTTPS destination URL', () => {
      const vo = WebhookUrl.create('https://alerts.enterprise.com/webhook');
      expect(vo.value).toBe('https://alerts.enterprise.com/webhook');
    });

    it('accepts localhost HTTP for local testing', () => {
      const vo1 = WebhookUrl.create('http://localhost:9000/webhook');
      const vo2 = WebhookUrl.create('http://127.0.0.1:8080/hook');
      expect(vo1.value).toBe('http://localhost:9000/webhook');
      expect(vo2.value).toBe('http://127.0.0.1:8080/hook');
    });

    it('rejects HTTP for remote public destinations', () => {
      expect(() =>
        WebhookUrl.create('http://insecure-alerts.com/hook'),
      ).toThrow(/must use HTTPS/);
    });

    it('rejects AWS/GCP link-local metadata IP (169.254.169.254)', () => {
      expect(() =>
        WebhookUrl.create('https://169.254.169.254/latest/meta-data/'),
      ).toThrow(/SSRF Protection Violation/);
    });

    it('rejects any link-local subnet destination (169.254.x.x)', () => {
      expect(() =>
        WebhookUrl.create('https://169.254.20.10/metadata'),
      ).toThrow(/SSRF Protection Violation/);
    });

    it('rejects unspecified wildcard IP (0.0.0.0)', () => {
      expect(() =>
        WebhookUrl.create('https://0.0.0.0/webhook'),
      ).toThrow(/SSRF Protection Violation/);
    });

    it('rejects Google Cloud metadata internal domain', () => {
      expect(() =>
        WebhookUrl.create('https://metadata.google.internal/computeMetadata/v1/'),
      ).toThrow(/SSRF Protection Violation/);
    });
  });

  describe('HMAC-SHA256 Webhook Signatures', () => {
    it('generates reproducible sha256=<hex> signature', () => {
      const secret = 'waf_whsec_test_secret_12345';
      const payload = JSON.stringify({ event: 'ATTACK_SPIKE', count: 12 });
      const signature = signWebhookPayload(payload, secret);

      expect(signature).toMatch(/^sha256=[a-f0-9]{64}$/);
    });

    it('successfully verifies valid signature', () => {
      const secret = 'waf_whsec_secret_abc';
      const payload = '{"message":"test"}';
      const signature = signWebhookPayload(payload, secret);

      expect(verifyWebhookSignature(payload, secret, signature)).toBe(true);
    });

    it('rejects tampered payload or incorrect secret', () => {
      const secret = 'waf_whsec_secret_abc';
      const payload = '{"message":"test"}';
      const signature = signWebhookPayload(payload, secret);

      expect(verifyWebhookSignature('{"message":"tampered"}', secret, signature)).toBe(false);
      expect(verifyWebhookSignature(payload, 'wrong_secret', signature)).toBe(false);
      expect(verifyWebhookSignature(payload, secret, 'invalid_header_format')).toBe(false);
    });
  });

  describe('Notification Entity Lifecycle', () => {
    it('creates unread notification and marks as read with timestamp', () => {
      const notif = Notification.create('notif-1', {
        tenantId: 'tenant-1',
        severity: 'CRITICAL',
        type: 'ATTACK_SPIKE',
        title: 'Attack Spike Alert',
        message: 'Multiple blocked events observed',
      });

      expect(notif.isRead).toBe(false);
      expect(notif.readAt).toBeNull();

      notif.markAsRead();
      expect(notif.isRead).toBe(true);
      expect(notif.readAt).toBeInstanceOf(Date);
    });
  });

  describe('Alert Evaluator Domain Logic', () => {
    it('returns empty triggers when no events provided or below threshold', () => {
      const triggers = evaluateAlertTriggers([
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'ALLOW' },
      ]);
      expect(triggers).toHaveLength(0);
    });

    it('triggers ATTACK_SPIKE when site exceeds >= 5 BLOCK events in batch', () => {
      const events = [
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-2', action: 'ALLOW' },
      ];

      const triggers = evaluateAlertTriggers(events);
      expect(triggers).toHaveLength(1);
      expect(triggers[0].type).toBe('ATTACK_SPIKE');
      expect(triggers[0].severity).toBe('CRITICAL');
      expect(triggers[0].siteId).toBe('site-1');
      expect(triggers[0].metadata.blockedCount).toBe(5);
    });

    it('triggers ML_DEGRADED when any event has degradedMode === true', () => {
      const events = [
        { siteId: 'site-1', action: 'MONITOR', degradedMode: true, requestId: 'req-deg-1' },
      ];

      const triggers = evaluateAlertTriggers(events);
      expect(triggers).toHaveLength(1);
      expect(triggers[0].type).toBe('ML_DEGRADED');
      expect(triggers[0].severity).toBe('WARNING');
      expect(triggers[0].metadata.requestId).toBe('req-deg-1');
    });

    it('detects both ATTACK_SPIKE and ML_DEGRADED simultaneously', () => {
      const events = [
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'BLOCK' },
        { siteId: 'site-1', action: 'ALLOW', degradedMode: true },
      ];

      const triggers = evaluateAlertTriggers(events);
      expect(triggers).toHaveLength(2);
      const types = triggers.map((t) => t.type);
      expect(types).toContain('ATTACK_SPIKE');
      expect(types).toContain('ML_DEGRADED');
    });
  });
});
