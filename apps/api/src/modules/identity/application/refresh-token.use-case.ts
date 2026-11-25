import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { RefreshSession } from '../domain/refresh-session.entity';
import {
  IUserRepository,
  IMembershipRepository,
  IRefreshSessionRepository,
  USER_REPOSITORY,
  MEMBERSHIP_REPOSITORY,
  REFRESH_SESSION_REPOSITORY,
} from '../domain/identity.repository.interfaces';
import { ITokenService, TOKEN_SERVICE } from '../infrastructure/token.service';

export interface RefreshResultDto {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class RefreshTokenUseCase {
  constructor(
    @Inject(USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(MEMBERSHIP_REPOSITORY) private readonly memberRepo: IMembershipRepository,
    @Inject(REFRESH_SESSION_REPOSITORY) private readonly sessionRepo: IRefreshSessionRepository,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
  ) {}

  async execute(refreshToken: string): Promise<Result<RefreshResultDto>> {
    if (!refreshToken || refreshToken.trim().length === 0) {
      return Result.fail<RefreshResultDto>('Missing refresh token');
    }

    const tokenHash = this.tokenService.hashToken(refreshToken);
    const session = await this.sessionRepo.findByTokenHash(tokenHash);

    if (!session) {
      return Result.fail<RefreshResultDto>('Invalid refresh token');
    }

    // Reuse detection: If session was already revoked -> someone is trying to reuse a leaked token!
    if (session.isRevoked) {
      // Immediate security penalty: revoke ALL sessions for this user
      await this.sessionRepo.revokeAllForUser(session.userId);
      return Result.fail<RefreshResultDto>('Token reuse detected. All sessions revoked.');
    }

    // Expiration check
    if (session.isExpired) {
      session.revoke();
      await this.sessionRepo.save(session);
      return Result.fail<RefreshResultDto>('Refresh token has expired');
    }

    // Revoke old session (Rotation)
    session.revoke();
    await this.sessionRepo.save(session);

    // Fetch user and membership
    const user = await this.userRepo.findById(session.userId);
    if (!user || !user.isActive) {
      return Result.fail<RefreshResultDto>('User inactive or not found');
    }

    const membership = await this.memberRepo.findByTenantAndUser(session.tenantId, user.id);
    if (!membership) {
      return Result.fail<RefreshResultDto>('Membership not found');
    }

    // Issue fresh pair
    const refreshData = this.tokenService.generateRefreshToken();
    const newSession = RefreshSession.create({
      userId: user.id,
      tenantId: membership.tenantId,
      tokenHash: refreshData.tokenHash,
      expiresAt: refreshData.expiresAt,
    }).getValue();
    await this.sessionRepo.save(newSession);

    const accessToken = this.tokenService.generateAccessToken({
      sub: user.id,
      tenantId: membership.tenantId,
      role: membership.role,
      email: user.email.value,
    });

    return Result.ok<RefreshResultDto>({
      accessToken,
      refreshToken: refreshData.token,
    });
  }
}
