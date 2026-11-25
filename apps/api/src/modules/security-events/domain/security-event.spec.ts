import { SecurityEvent } from './security-event.entity';
import { EventFeedback } from './event-feedback.entity';
import {
  WafAction,
  SecuritySeverity,
  FeedbackLabel,
  FeedbackReviewStatus,
} from './security-event.types';
import { sanitizeRedactedPayload } from './sanitize-payload';

describe('Security Events & False-Positive Feedback Domain Entities', () => {
  describe('sanitizeRedactedPayload Domain Safety Net', () => {
    it('redacts sensitive headers and fields in nested objects', () => {
      const rawPayload = {
        headers: {
          host: 'api.example.com',
          authorization: 'Bearer super-secret-oauth-token',
          cookie: 'session_id=abcdef12345; other=val',
          'set-cookie': 'secret=123',
        },
        body: {
          username: 'alice',
          password: 'SecretPassword123!',
          apiKey: 'key_live_99887766',
          nested: {
            token: 'jwt.token.here',
            publicInfo: 'harmless',
          },
        },
      };

      const sanitized = sanitizeRedactedPayload(rawPayload);

      expect(sanitized.headers.host).toBe('api.example.com');
      expect(sanitized.headers.authorization).toBe('[REDACTED]');
      expect(sanitized.headers.cookie).toBe('[REDACTED]');
      expect(sanitized.headers['set-cookie']).toBe('[REDACTED]');
      expect(sanitized.body.username).toBe('alice');
      expect(sanitized.body.password).toBe('[REDACTED]');
      expect(sanitized.body.apiKey).toBe('[REDACTED]');
      expect(sanitized.body.nested.token).toBe('[REDACTED]');
      expect(sanitized.body.nested.publicInfo).toBe('harmless');
    });

    it('redacts bearer tokens and passwords in raw strings', () => {
      const rawStr = 'GET /login?password=mysecret&user=alice with Bearer ya29.abcdef';
      const sanitized = sanitizeRedactedPayload(rawStr);
      expect(sanitized).toContain('password=[REDACTED]');
      expect(sanitized).toContain('Bearer [REDACTED]');
    });
  });

  describe('SecurityEvent Entity', () => {
    it('creates security event and automatically computes severity and clamps riskScore', () => {
      const res = SecurityEvent.create({
        tenantId: 'tenant-123',
        siteId: 'site-456',
        requestId: 'req-001',
        method: 'POST',
        path: '/admin/upload',
        action: WafAction.BLOCK,
        riskScore: 0.95,
        latencyMs: 12.4,
        redactedRequest: {
          headers: {
            authorization: 'Bearer secret-token',
            host: 'admin.acme.com',
          },
        },
      });

      expect(res.isSuccess).toBe(true);
      const event = res.getValue();
      expect(event.tenantId).toBe('tenant-123');
      expect(event.action).toBe(WafAction.BLOCK);
      expect(event.severity).toBe(SecuritySeverity.HIGH);
      expect(event.riskScore).toBe(0.95);
      expect(event.redactedRequest.headers.authorization).toBe('[REDACTED]');
      expect(event.redactedRequest.headers.host).toBe('admin.acme.com');
    });

    it('rejects creation when required fields are missing', () => {
      const res = SecurityEvent.create({
        tenantId: '',
        requestId: 'req-002',
        method: 'GET',
        path: '/api',
        action: WafAction.ALLOW,
      });

      expect(res.isFailure).toBe(true);
      expect(res.getError()).toContain('tenantId');
    });
  });

  describe('EventFeedback Entity & Review State Machine', () => {
    it('creates feedback in PENDING_REVIEW status', () => {
      const res = EventFeedback.create({
        tenantId: 'tenant-123',
        siteId: 'site-456',
        securityEventId: 'event-789',
        submittedByUserId: 'user-analyst',
        label: FeedbackLabel.FALSE_POSITIVE,
        notes: 'Harmful signature matched harmless string in search bar',
      });

      expect(res.isSuccess).toBe(true);
      const feedback = res.getValue();
      expect(feedback.reviewStatus).toBe(FeedbackReviewStatus.PENDING_REVIEW);
      expect(feedback.label).toBe(FeedbackLabel.FALSE_POSITIVE);
      expect(feedback.reviewerUserId).toBeNull();
      expect(feedback.reviewedAt).toBeNull();
    });

    it('approves pending feedback and sets reviewer metadata', () => {
      const feedback = EventFeedback.create({
        tenantId: 'tenant-123',
        securityEventId: 'event-789',
        label: FeedbackLabel.FALSE_POSITIVE,
      }).getValue();

      const approveRes = feedback.approve('user-admin', 'Verified benign parameter; queued for offline dataset');
      expect(approveRes.isSuccess).toBe(true);
      expect(feedback.reviewStatus).toBe(FeedbackReviewStatus.APPROVED);
      expect(feedback.reviewerUserId).toBe('user-admin');
      expect(feedback.reviewNotes).toContain('Verified benign parameter');
      expect(feedback.reviewedAt).toBeDefined();

      // Invariant: Cannot re-review already finalized feedback
      const secondApprove = feedback.approve('user-other');
      expect(secondApprove.isFailure).toBe(true);
      expect(secondApprove.getError()).toContain('must be PENDING_REVIEW');
    });

    it('rejects pending feedback and sets reviewer metadata', () => {
      const feedback = EventFeedback.create({
        tenantId: 'tenant-123',
        securityEventId: 'event-789',
        label: FeedbackLabel.FALSE_POSITIVE,
      }).getValue();

      const rejectRes = feedback.reject('user-admin', 'Actual XSS payload; block confirmed');
      expect(rejectRes.isSuccess).toBe(true);
      expect(feedback.reviewStatus).toBe(FeedbackReviewStatus.REJECTED);
      expect(feedback.reviewerUserId).toBe('user-admin');

      // Invariant: Cannot re-review already finalized feedback
      const reReject = feedback.reject('user-other');
      expect(reReject.isFailure).toBe(true);
    });
  });
});
