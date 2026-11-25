import { User } from '../domain/user.entity';
import { Email } from '../domain/email.vo';
import { Membership } from '../domain/membership.entity';
import { RefreshSession } from '../domain/refresh-session.entity';
import { AuditLog } from '../domain/audit-log.entity';
import {
  IUserRepository,
  IMembershipRepository,
  IRefreshSessionRepository,
  IAuditLogRepository,
} from '../domain/identity.repository.interfaces';

export class InMemoryUserRepository implements IUserRepository {
  private users: Map<string, User> = new Map();

  async findById(id: string): Promise<User | null> {
    return this.users.get(id) ?? null;
  }

  async findByEmail(email: Email): Promise<User | null> {
    for (const u of this.users.values()) {
      if (u.email.value === email.value) {
        return u;
      }
    }
    return null;
  }

  async save(user: User): Promise<void> {
    this.users.set(user.id, user);
  }

  async exists(email: Email): Promise<boolean> {
    const found = await this.findByEmail(email);
    return found !== null;
  }

  clear() {
    this.users.clear();
  }
}

export class InMemoryMembershipRepository implements IMembershipRepository {
  private memberships: Map<string, Membership> = new Map();

  async findById(id: string): Promise<Membership | null> {
    return this.memberships.get(id) ?? null;
  }

  async findByTenantAndUser(tenantId: string, userId: string): Promise<Membership | null> {
    for (const m of this.memberships.values()) {
      if (m.tenantId === tenantId && m.userId === userId) {
        return m;
      }
    }
    return null;
  }

  async findByUser(userId: string): Promise<Membership[]> {
    return Array.from(this.memberships.values()).filter((m) => m.userId === userId);
  }

  async findByTenant(tenantId: string): Promise<Membership[]> {
    return Array.from(this.memberships.values()).filter((m) => m.tenantId === tenantId);
  }

  async save(membership: Membership): Promise<void> {
    this.memberships.set(membership.id, membership);
  }

  async delete(id: string): Promise<void> {
    this.memberships.delete(id);
  }

  clear() {
    this.memberships.clear();
  }
}

export class InMemoryRefreshSessionRepository implements IRefreshSessionRepository {
  private sessions: Map<string, RefreshSession> = new Map();

  async findByTokenHash(tokenHash: string): Promise<RefreshSession | null> {
    for (const s of this.sessions.values()) {
      if (s.tokenHash === tokenHash) {
        return s;
      }
    }
    return null;
  }

  async findByUser(userId: string): Promise<RefreshSession[]> {
    return Array.from(this.sessions.values()).filter((s) => s.userId === userId);
  }

  async save(session: RefreshSession): Promise<void> {
    this.sessions.set(session.id, session);
  }

  async revokeAllForUser(userId: string): Promise<void> {
    for (const s of this.sessions.values()) {
      if (s.userId === userId && !s.isRevoked) {
        s.revoke();
      }
    }
  }

  clear() {
    this.sessions.clear();
  }
}

export class InMemoryAuditLogRepository implements IAuditLogRepository {
  private logs: AuditLog[] = [];

  async save(log: AuditLog): Promise<void> {
    this.logs.push(log);
  }

  async findByTenant(tenantId: string, limit = 50): Promise<AuditLog[]> {
    return this.logs
      .filter((l) => l.tenantId === tenantId)
      .slice(-limit)
      .reverse();
  }

  clear() {
    this.logs = [];
  }
}
