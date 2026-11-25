import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { Email } from '../domain/email.vo';
import { RefreshSession } from '../domain/refresh-session.entity';
import { AuditLog } from '../domain/audit-log.entity';
import {
  IUserRepository,
  IMembershipRepository,
  IRefreshSessionRepository,
  IAuditLogRepository,
  USER_REPOSITORY,
  MEMBERSHIP_REPOSITORY,
  REFRESH_SESSION_REPOSITORY,
  AUDIT_LOG_REPOSITORY,
} from '../domain/identity.repository.interfaces';
import { IPasswordHasher, PASSWORD_HASHER } from '../infrastructure/password-hasher.service';
import { ITokenService, TOKEN_SERVICE } from '../infrastructure/token.service';
import { LoginRequestDto } from '../presentation/dtos/auth.request.dtos';
import { AuthSessionResponseDto } from './dtos/identity.dto';

@Injectable()
export class LoginUseCase {
  constructor(
    @Inject(USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(MEMBERSHIP_REPOSITORY) private readonly memberRepo: IMembershipRepository,
    @Inject(REFRESH_SESSION_REPOSITORY) private readonly sessionRepo: IRefreshSessionRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
    @Inject(PASSWORD_HASHER) private readonly hasher: IPasswordHasher,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
  ) {}

  async execute(dto: LoginRequestDto, clientIp?: string): Promise<Result<AuthSessionResponseDto>> {
    const invalidCredentialsMsg = 'Invalid email or password';

    const emailRes = Email.create(dto.email);
    if (emailRes.isFailure) {
      return Result.fail<AuthSessionResponseDto>(invalidCredentialsMsg);
    }

    const user = await this.userRepo.findByEmail(emailRes.getValue());
    if (!user || !user.isActive) {
      return Result.fail<AuthSessionResponseDto>(invalidCredentialsMsg);
    }

    const passwordMatches = await this.hasher.compare(dto.password, user.passwordHash);
    if (!passwordMatches) {
      return Result.fail<AuthSessionResponseDto>(invalidCredentialsMsg);
    }

    // Retrieve active tenant membership (first membership or highest role)
    const memberships = await this.memberRepo.findByUser(user.id);
    if (memberships.length === 0) {
      return Result.fail<AuthSessionResponseDto>('User does not belong to any tenant');
    }

    const activeMembership = memberships[0];

    // Issue Token Pair & Session
    const refreshData = this.tokenService.generateRefreshToken();
    const session = RefreshSession.create({
      userId: user.id,
      tenantId: activeMembership.tenantId,
      tokenHash: refreshData.tokenHash,
      expiresAt: refreshData.expiresAt,
    }).getValue();
    await this.sessionRepo.save(session);

    const accessToken = this.tokenService.generateAccessToken({
      sub: user.id,
      tenantId: activeMembership.tenantId,
      role: activeMembership.role,
      email: user.email.value,
    });

    // Record USER_LOGIN audit event
    const auditLog = AuditLog.create({
      tenantId: activeMembership.tenantId,
      userId: user.id,
      action: 'USER_LOGIN',
      resource: 'User',
      resourceId: user.id,
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(auditLog);

    return Result.ok<AuthSessionResponseDto>({
      user: {
        id: user.id,
        email: user.email.value,
        name: user.name,
        isActive: user.isActive,
        createdAt: user.createdAt.toISOString(),
      },
      activeTenantId: activeMembership.tenantId,
      role: activeMembership.role,
      accessToken,
      refreshToken: refreshData.token,
    });
  }
}
