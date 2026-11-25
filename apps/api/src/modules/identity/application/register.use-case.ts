import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { Email } from '../domain/email.vo';
import { User } from '../domain/user.entity';
import { Membership } from '../domain/membership.entity';
import { RefreshSession } from '../domain/refresh-session.entity';
import { AuditLog } from '../domain/audit-log.entity';
import { UserRole } from '../domain/user-role';
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
import {
  ITenantRepository,
  TENANT_REPOSITORY,
} from '../../tenants/domain/tenant.repository.interface';
import { Tenant } from '../../tenants/domain/tenant.entity';
import { TenantSlug } from '../../tenants/domain/tenant-slug.vo';
import { IPasswordHasher, PASSWORD_HASHER } from '../infrastructure/password-hasher.service';
import { ITokenService, TOKEN_SERVICE } from '../infrastructure/token.service';
import { RegisterRequestDto } from '../presentation/dtos/auth.request.dtos';
import { AuthSessionResponseDto } from './dtos/identity.dto';

@Injectable()
export class RegisterUseCase {
  constructor(
    @Inject(USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(TENANT_REPOSITORY) private readonly tenantRepo: ITenantRepository,
    @Inject(MEMBERSHIP_REPOSITORY) private readonly memberRepo: IMembershipRepository,
    @Inject(REFRESH_SESSION_REPOSITORY) private readonly sessionRepo: IRefreshSessionRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
    @Inject(PASSWORD_HASHER) private readonly hasher: IPasswordHasher,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
  ) {}

  async execute(dto: RegisterRequestDto, clientIp?: string): Promise<Result<AuthSessionResponseDto>> {
    const emailRes = Email.create(dto.email);
    if (emailRes.isFailure) return Result.fail<AuthSessionResponseDto>(emailRes.getError());
    const email = emailRes.getValue();

    const emailExists = await this.userRepo.exists(email);
    if (emailExists) {
      return Result.fail<AuthSessionResponseDto>('User with this email already exists');
    }

    const slugRes = TenantSlug.create(dto.tenantSlug);
    if (slugRes.isFailure) return Result.fail<AuthSessionResponseDto>(slugRes.getError());
    const slug = slugRes.getValue();

    const slugExists = await this.tenantRepo.exists(slug);
    if (slugExists) {
      return Result.fail<AuthSessionResponseDto>(`Tenant with slug '${slug.value}' already exists`);
    }

    // 1. Create User
    const passwordHash = await this.hasher.hash(dto.password);
    const user = User.create({
      email,
      passwordHash,
      name: dto.fullName ?? null,
    }).getValue();

    // 2. Create Tenant
    const tenant = Tenant.create({
      name: dto.tenantName,
      slug,
    }).getValue();

    // 3. Create Membership as OWNER
    const membership = Membership.create({
      tenantId: tenant.id.value,
      userId: user.id,
      role: UserRole.OWNER,
    }).getValue();

    // Persist
    await this.userRepo.save(user);
    await this.tenantRepo.save(tenant);
    await this.memberRepo.save(membership);

    // 4. Create Refresh Session & Token Pair
    const refreshData = this.tokenService.generateRefreshToken();
    const session = RefreshSession.create({
      userId: user.id,
      tenantId: tenant.id.value,
      tokenHash: refreshData.tokenHash,
      expiresAt: refreshData.expiresAt,
    }).getValue();
    await this.sessionRepo.save(session);

    const accessToken = this.tokenService.generateAccessToken({
      sub: user.id,
      tenantId: tenant.id.value,
      role: UserRole.OWNER,
      email: user.email.value,
    });

    // 5. Audit Log
    const auditLog = AuditLog.create({
      tenantId: tenant.id.value,
      userId: user.id,
      action: 'USER_REGISTERED',
      resource: 'User',
      resourceId: user.id,
      metadata: { email: user.email.value, tenantSlug: slug.value },
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
      activeTenantId: tenant.id.value,
      role: UserRole.OWNER,
      accessToken,
      refreshToken: refreshData.token,
    });
  }
}
