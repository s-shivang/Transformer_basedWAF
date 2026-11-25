import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';

export interface AccessTokenPayload {
  sub: string; // userId
  tenantId: string;
  role: string;
  email: string;
}

export interface ITokenService {
  generateAccessToken(payload: AccessTokenPayload): string;
  verifyAccessToken(token: string): AccessTokenPayload | null;
  generateRefreshToken(): { token: string; tokenHash: string; expiresAt: Date };
  hashToken(token: string): string;
}

export const TOKEN_SERVICE = Symbol('ITokenService');

export class JwtTokenService implements ITokenService {
  private readonly accessSecret: string;
  private readonly accessExpiresIn: string = '15m';
  private readonly refreshExpiresDays: number = 7;

  constructor() {
    this.accessSecret = process.env.JWT_ACCESS_SECRET || 'dev_jwt_access_secret_super_secure_32chars!';
  }

  generateAccessToken(payload: AccessTokenPayload): string {
    return jwt.sign(payload, this.accessSecret, {
      expiresIn: this.accessExpiresIn as any,
    });
  }

  verifyAccessToken(token: string): AccessTokenPayload | null {
    try {
      const decoded = jwt.verify(token, this.accessSecret) as AccessTokenPayload;
      return decoded;
    } catch {
      return null;
    }
  }

  generateRefreshToken(): { token: string; tokenHash: string; expiresAt: Date } {
    const rawBytes = crypto.randomBytes(32).toString('hex');
    const tokenHash = this.hashToken(rawBytes);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.refreshExpiresDays);

    return {
      token: rawBytes,
      tokenHash,
      expiresAt,
    };
  }

  hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}
