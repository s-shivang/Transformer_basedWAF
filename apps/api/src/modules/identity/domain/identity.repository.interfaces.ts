import { User } from './user.entity';
import { Email } from './email.vo';
import { Membership } from './membership.entity';
import { RefreshSession } from './refresh-session.entity';
import { AuditLog } from './audit-log.entity';

export const USER_REPOSITORY = Symbol('IUserRepository');
export const MEMBERSHIP_REPOSITORY = Symbol('IMembershipRepository');
export const REFRESH_SESSION_REPOSITORY = Symbol('IRefreshSessionRepository');
export const AUDIT_LOG_REPOSITORY = Symbol('IAuditLogRepository');

export interface IUserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: Email): Promise<User | null>;
  save(user: User): Promise<void>;
  exists(email: Email): Promise<boolean>;
}

export interface IMembershipRepository {
  findById(id: string): Promise<Membership | null>;
  findByTenantAndUser(tenantId: string, userId: string): Promise<Membership | null>;
  findByUser(userId: string): Promise<Membership[]>;
  findByTenant(tenantId: string): Promise<Membership[]>;
  save(membership: Membership): Promise<void>;
  delete(id: string): Promise<void>;
}

export interface IRefreshSessionRepository {
  findByTokenHash(tokenHash: string): Promise<RefreshSession | null>;
  findByUser(userId: string): Promise<RefreshSession[]>;
  save(session: RefreshSession): Promise<void>;
  revokeAllForUser(userId: string): Promise<void>;
}

export interface IAuditLogRepository {
  save(log: AuditLog): Promise<void>;
  findByTenant(tenantId: string, limit?: number): Promise<AuditLog[]>;
}
