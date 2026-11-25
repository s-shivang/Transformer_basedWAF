import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { AuditLog } from '../domain/audit-log.entity';
import {
  IRefreshSessionRepository,
  IAuditLogRepository,
  REFRESH_SESSION_REPOSITORY,
  AUDIT_LOG_REPOSITORY,
} from '../domain/identity.repository.interfaces';
import { ITokenService, TOKEN_SERVICE } from '../infrastructure/token.service';

@Injectable()
export class LogoutUseCase {
  constructor(
    @Inject(REFRESH_SESSION_REPOSITORY) private readonly sessionRepo: IRefreshSessionRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
  ) {}

  async execute(refreshToken?: string, userId?: string, tenantId?: string, clientIp?: string): Promise<Result<void>> {
    if (refreshToken) {
      const tokenHash = this.tokenService.hashToken(refreshToken);
      const session = await this.sessionRepo.findByTokenHash(tokenHash);
      if (session && !session.isRevoked) {
        session.revoke();
        await this.sessionRepo.save(session);
      }
    }

    if (userId && tenantId) {
      const audit = AuditLog.create({
        tenantId,
        userId,
        action: 'LOGOUT',
        resource: 'User',
        resourceId: userId,
        ipAddress: clientIp,
      }).getValue();
      await this.auditRepo.save(audit);
    }

    return Result.ok<void>();
  }
}
