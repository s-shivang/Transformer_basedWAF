import { Email } from './email.vo';
import { UserRole, hasRequiredRole } from './user-role';
import { User } from './user.entity';
import { Membership } from './membership.entity';
import { RefreshSession } from './refresh-session.entity';
import { BcryptPasswordHasher } from '../infrastructure/password-hasher.service';
import { JwtTokenService } from '../infrastructure/token.service';

describe('Identity Domain & Infrastructure Security Invariants', () => {
  describe('Email Value Object', () => {
    it('should validate and normalize valid email', () => {
      const res = Email.create('  Admin@ACME.Com  ');
      expect(res.isSuccess).toBe(true);
      expect(res.getValue().value).toBe('admin@acme.com');
    });

    it('should reject invalid email formats', () => {
      expect(Email.create('invalid-email').isFailure).toBe(true);
      expect(Email.create('@domain.com').isFailure).toBe(true);
      expect(Email.create('user@').isFailure).toBe(true);
      expect(Email.create('').isFailure).toBe(true);
    });
  });

  describe('UserRole Hierarchy & Helper', () => {
    it('should grant OWNER access to all lower role requirements', () => {
      expect(hasRequiredRole(UserRole.OWNER, [UserRole.VIEWER])).toBe(true);
      expect(hasRequiredRole(UserRole.OWNER, [UserRole.ANALYST])).toBe(true);
      expect(hasRequiredRole(UserRole.OWNER, [UserRole.ADMIN])).toBe(true);
      expect(hasRequiredRole(UserRole.OWNER, [UserRole.OWNER])).toBe(true);
    });

    it('should deny VIEWER access to ADMIN or OWNER actions', () => {
      expect(hasRequiredRole(UserRole.VIEWER, [UserRole.OWNER])).toBe(false);
      expect(hasRequiredRole(UserRole.VIEWER, [UserRole.ADMIN])).toBe(false);
      expect(hasRequiredRole(UserRole.VIEWER, [UserRole.VIEWER])).toBe(true);
    });

    it('should correctly evaluate ADMIN permissions', () => {
      expect(hasRequiredRole(UserRole.ADMIN, [UserRole.OWNER])).toBe(false);
      expect(hasRequiredRole(UserRole.ADMIN, [UserRole.ADMIN, UserRole.OWNER])).toBe(true);
      expect(hasRequiredRole(UserRole.ADMIN, [UserRole.ANALYST])).toBe(true);
    });
  });

  describe('Password Hashing Service (bcryptjs)', () => {
    const hasher = new BcryptPasswordHasher();

    it('should hash and verify passwords correctly', async () => {
      const plain = 'StrongSecretP@ss123';
      const hash = await hasher.hash(plain);

      expect(hash).not.toBe(plain);
      expect(hash.startsWith('$2')).toBe(true);

      const isValid = await hasher.compare(plain, hash);
      expect(isValid).toBe(true);

      const isInvalid = await hasher.compare('WrongPassword', hash);
      expect(isInvalid).toBe(false);
    });
  });

  describe('Token Service (JWT Access & Opaque Refresh Tokens)', () => {
    const tokenService = new JwtTokenService();

    it('should generate and verify valid access tokens', () => {
      const payload = {
        sub: 'user-123',
        tenantId: 'tenant-abc',
        role: UserRole.OWNER,
        email: 'owner@acme.com',
      };

      const token = tokenService.generateAccessToken(payload);
      expect(typeof token).toBe('string');

      const verified = tokenService.verifyAccessToken(token);
      expect(verified).not.toBeNull();
      expect(verified?.sub).toBe(payload.sub);
      expect(verified?.tenantId).toBe(payload.tenantId);
      expect(verified?.role).toBe(payload.role);
    });

    it('should reject invalid or tampered access tokens', () => {
      const verified = tokenService.verifyAccessToken('invalid.jwt.token');
      expect(verified).toBeNull();
    });

    it('should generate secure refresh tokens and deterministic SHA-256 hashes', () => {
      const data1 = tokenService.generateRefreshToken();
      expect(data1.token.length).toBe(64); // 32 bytes hex
      expect(data1.tokenHash).toBe(tokenService.hashToken(data1.token));
      expect(data1.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });
  });

  describe('RefreshSession Entity', () => {
    it('should track revocation correctly', () => {
      const session = RefreshSession.create({
        userId: 'u1',
        tenantId: 't1',
        tokenHash: 'hash123',
        expiresAt: new Date(Date.now() + 100000),
      }).getValue();

      expect(session.isRevoked).toBe(false);
      session.revoke();
      expect(session.isRevoked).toBe(true);
    });
  });
});
