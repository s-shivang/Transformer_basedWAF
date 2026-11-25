import { Injectable } from '@nestjs/common';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import { User } from '../domain/user.entity';
import { Email } from '../domain/email.vo';
import { Membership } from '../domain/membership.entity';
import { RefreshSession } from '../domain/refresh-session.entity';
import { AuditLog } from '../domain/audit-log.entity';
import { UserRole } from '../domain/user-role';
import {
  IUserRepository,
  IMembershipRepository,
  IRefreshSessionRepository,
  IAuditLogRepository,
} from '../domain/identity.repository.interfaces';

@Injectable()
export class PrismaUserRepository implements IUserRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById(id: string): Promise<User | null> {
    const record = await this.prisma.user.findUnique({ where: { id } });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findByEmail(email: Email): Promise<User | null> {
    const record = await this.prisma.user.findUnique({ where: { email: email.value } });
    if (!record) return null;
    return this.toDomain(record);
  }

  async save(user: User): Promise<void> {
    await this.prisma.user.upsert({
      where: { id: user.id },
      create: {
        id: user.id,
        email: user.email.value,
        passwordHash: user.passwordHash,
        name: user.name,
        isActive: user.isActive,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
      update: {
        email: user.email.value,
        passwordHash: user.passwordHash,
        name: user.name,
        isActive: user.isActive,
        updatedAt: user.updatedAt,
      },
    });
  }

  async exists(email: Email): Promise<boolean> {
    const count = await this.prisma.user.count({ where: { email: email.value } });
    return count > 0;
  }

  private toDomain(record: any): User {
    return User.reconstitute(record.id, {
      email: Email.create(record.email).getValue(),
      passwordHash: record.passwordHash,
      name: record.name,
      isActive: record.isActive,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    });
  }
}

@Injectable()
export class PrismaMembershipRepository implements IMembershipRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById(id: string): Promise<Membership | null> {
    const record = await this.prisma.membership.findUnique({ where: { id } });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findByTenantAndUser(tenantId: string, userId: string): Promise<Membership | null> {
    const record = await this.prisma.membership.findUnique({
      where: { tenantId_userId: { tenantId, userId } },
    });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findByUser(userId: string): Promise<Membership[]> {
    const records = await this.prisma.membership.findMany({ where: { userId } });
    return records.map((r) => this.toDomain(r));
  }

  async findByTenant(tenantId: string): Promise<Membership[]> {
    const records = await this.prisma.membership.findMany({ where: { tenantId } });
    return records.map((r) => this.toDomain(r));
  }

  async save(membership: Membership): Promise<void> {
    await this.prisma.membership.upsert({
      where: { id: membership.id },
      create: {
        id: membership.id,
        tenantId: membership.tenantId,
        userId: membership.userId,
        role: membership.role as any,
        createdAt: membership.createdAt,
        updatedAt: membership.updatedAt,
      },
      update: {
        role: membership.role as any,
        updatedAt: membership.updatedAt,
      },
    });
  }

  async delete(id: string): Promise<void> {
    await this.prisma.membership.delete({ where: { id } });
  }

  private toDomain(record: any): Membership {
    return Membership.reconstitute(record.id, {
      tenantId: record.tenantId,
      userId: record.userId,
      role: record.role as UserRole,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    });
  }
}

@Injectable()
export class PrismaRefreshSessionRepository implements IRefreshSessionRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findByTokenHash(tokenHash: string): Promise<RefreshSession | null> {
    const record = await this.prisma.refreshSession.findUnique({ where: { tokenHash } });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findByUser(userId: string): Promise<RefreshSession[]> {
    const records = await this.prisma.refreshSession.findMany({ where: { userId } });
    return records.map((r) => this.toDomain(r));
  }

  async save(session: RefreshSession): Promise<void> {
    await this.prisma.refreshSession.upsert({
      where: { id: session.id },
      create: {
        id: session.id,
        userId: session.userId,
        tenantId: session.tenantId,
        tokenHash: session.tokenHash,
        expiresAt: session.expiresAt,
        revokedAt: session.revokedAt,
        createdAt: session.createdAt,
      },
      update: {
        revokedAt: session.revokedAt,
      },
    });
  }

  async revokeAllForUser(userId: string): Promise<void> {
    await this.prisma.refreshSession.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  private toDomain(record: any): RefreshSession {
    return RefreshSession.reconstitute(record.id, {
      userId: record.userId,
      tenantId: record.tenantId,
      tokenHash: record.tokenHash,
      expiresAt: record.expiresAt,
      revokedAt: record.revokedAt,
      createdAt: record.createdAt,
    });
  }
}

@Injectable()
export class PrismaAuditLogRepository implements IAuditLogRepository {
  constructor(private readonly prisma: PrismaService) {}

  async save(log: AuditLog): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        id: log.id,
        tenantId: log.tenantId,
        userId: log.userId,
        action: log.action,
        resource: log.resource,
        resourceId: log.resourceId,
        metadata: log.metadata,
        ipAddress: log.ipAddress,
        createdAt: log.createdAt,
      },
    });
  }

  async findByTenant(tenantId: string, limit = 50): Promise<AuditLog[]> {
    const records = await this.prisma.auditLog.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
    return records.map((r) =>
      AuditLog.reconstitute(r.id, {
        tenantId: r.tenantId,
        userId: r.userId,
        action: r.action,
        resource: r.resource,
        resourceId: r.resourceId,
        metadata: r.metadata,
        ipAddress: r.ipAddress,
        createdAt: r.createdAt,
      }),
    );
  }
}
