import { Inject, Injectable } from '@nestjs/common';
import { Result } from '@shared/application/result';
import { Email } from '../domain/email.vo';
import { User } from '../domain/user.entity';
import { Membership } from '../domain/membership.entity';
import { AuditLog } from '../domain/audit-log.entity';
import { UserRole } from '../domain/user-role';
import {
  IUserRepository,
  IMembershipRepository,
  IAuditLogRepository,
  USER_REPOSITORY,
  MEMBERSHIP_REPOSITORY,
  AUDIT_LOG_REPOSITORY,
} from '../domain/identity.repository.interfaces';
import { IPasswordHasher, PASSWORD_HASHER } from '../infrastructure/password-hasher.service';
import { AddMemberRequestDto } from '../presentation/dtos/auth.request.dtos';
import { MemberResponseDto } from './dtos/identity.dto';

@Injectable()
export class AddMemberUseCase {
  constructor(
    @Inject(USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(MEMBERSHIP_REPOSITORY) private readonly memberRepo: IMembershipRepository,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly auditRepo: IAuditLogRepository,
    @Inject(PASSWORD_HASHER) private readonly hasher: IPasswordHasher,
  ) {}

  async execute(
    tenantId: string,
    dto: AddMemberRequestDto,
    inviterRole: UserRole,
    inviterId: string,
    clientIp?: string,
  ): Promise<Result<MemberResponseDto>> {
    // Only OWNER or ADMIN can invite members
    if (inviterRole !== UserRole.OWNER && inviterRole !== UserRole.ADMIN) {
      return Result.fail<MemberResponseDto>('Only OWNER or ADMIN can add tenant members');
    }

    const targetRole = dto.role as UserRole;
    if (!Object.values(UserRole).includes(targetRole)) {
      return Result.fail<MemberResponseDto>(`Invalid role: ${dto.role}`);
    }

    // Only OWNER can assign OWNER role
    if (targetRole === UserRole.OWNER && inviterRole !== UserRole.OWNER) {
      return Result.fail<MemberResponseDto>('Only an OWNER can assign the OWNER role');
    }

    const emailRes = Email.create(dto.email);
    if (emailRes.isFailure) return Result.fail<MemberResponseDto>(emailRes.getError());
    const email = emailRes.getValue();

    // Check if user exists or create a placeholder user with a generated password
    let user = await this.userRepo.findByEmail(email);
    if (!user) {
      const defaultPasswordHash = await this.hasher.hash(crypto.randomUUID());
      user = User.create({
        email,
        passwordHash: defaultPasswordHash,
        name: dto.fullName ?? null,
      }).getValue();
      await this.userRepo.save(user);
    }

    // Check if user is already a member of this tenant
    const existingMembership = await this.memberRepo.findByTenantAndUser(tenantId, user.id);
    if (existingMembership) {
      return Result.fail<MemberResponseDto>('User is already a member of this tenant');
    }

    const membership = Membership.create({
      tenantId,
      userId: user.id,
      role: targetRole,
    }).getValue();
    await this.memberRepo.save(membership);

    // Record MEMBER_ADDED audit log
    const audit = AuditLog.create({
      tenantId,
      userId: inviterId,
      action: 'MEMBER_ADDED',
      resource: 'Membership',
      resourceId: membership.id,
      metadata: { targetUserId: user.id, role: targetRole },
      ipAddress: clientIp,
    }).getValue();
    await this.auditRepo.save(audit);

    return Result.ok<MemberResponseDto>({
      id: membership.id,
      tenantId: membership.tenantId,
      userId: membership.userId,
      role: membership.role,
      createdAt: membership.createdAt.toISOString(),
    });
  }
}

@Injectable()
export class ListMembersUseCase {
  constructor(@Inject(MEMBERSHIP_REPOSITORY) private readonly memberRepo: IMembershipRepository) {}

  async execute(tenantId: string): Promise<Result<MemberResponseDto[]>> {
    const members = await this.memberRepo.findByTenant(tenantId);
    return Result.ok<MemberResponseDto[]>(
      members.map((m) => ({
        id: m.id,
        tenantId: m.tenantId,
        userId: m.userId,
        role: m.role,
        createdAt: m.createdAt.toISOString(),
      })),
    );
  }
}
