import { Module, forwardRef } from '@nestjs/common';
import { AuthController, TenantMembersController } from './presentation/auth.controller';
import { RegisterUseCase } from './application/register.use-case';
import { LoginUseCase } from './application/login.use-case';
import { RefreshTokenUseCase } from './application/refresh-token.use-case';
import { LogoutUseCase } from './application/logout.use-case';
import { AddMemberUseCase, ListMembersUseCase } from './application/member-management.use-case';
import {
  USER_REPOSITORY,
  MEMBERSHIP_REPOSITORY,
  REFRESH_SESSION_REPOSITORY,
  AUDIT_LOG_REPOSITORY,
} from './domain/identity.repository.interfaces';
import {
  PrismaUserRepository,
  PrismaMembershipRepository,
  PrismaRefreshSessionRepository,
  PrismaAuditLogRepository,
} from './infrastructure/prisma-identity.repositories';
import { PASSWORD_HASHER, BcryptPasswordHasher } from './infrastructure/password-hasher.service';
import { TOKEN_SERVICE, JwtTokenService } from './infrastructure/token.service';
import { JwtAuthGuard } from './presentation/guards/jwt-auth.guard';
import { TenantScopeGuard } from './presentation/guards/tenant-scope.guard';
import { RolesGuard } from './presentation/guards/roles.guard';
import { TenantsModule } from '../tenants/tenants.module';
import { PrismaService } from '@shared/infrastructure/prisma.service';

@Module({
  imports: [forwardRef(() => TenantsModule)],
  controllers: [AuthController, TenantMembersController],
  providers: [
    RegisterUseCase,
    LoginUseCase,
    RefreshTokenUseCase,
    LogoutUseCase,
    AddMemberUseCase,
    ListMembersUseCase,
    PrismaService,
    JwtAuthGuard,
    TenantScopeGuard,
    RolesGuard,
    {
      provide: USER_REPOSITORY,
      useClass: PrismaUserRepository,
    },
    {
      provide: MEMBERSHIP_REPOSITORY,
      useClass: PrismaMembershipRepository,
    },
    {
      provide: REFRESH_SESSION_REPOSITORY,
      useClass: PrismaRefreshSessionRepository,
    },
    {
      provide: AUDIT_LOG_REPOSITORY,
      useClass: PrismaAuditLogRepository,
    },
    {
      provide: PASSWORD_HASHER,
      useClass: BcryptPasswordHasher,
    },
    {
      provide: TOKEN_SERVICE,
      useClass: JwtTokenService,
    },
  ],
  exports: [
    JwtAuthGuard,
    TenantScopeGuard,
    RolesGuard,
    TOKEN_SERVICE,
    USER_REPOSITORY,
    MEMBERSHIP_REPOSITORY,
    REFRESH_SESSION_REPOSITORY,
    AUDIT_LOG_REPOSITORY,
    PASSWORD_HASHER,
  ],
})
export class IdentityModule {}
