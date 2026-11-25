import { SecurityEvent } from '../domain/security-event.entity';
import { SecurityEventQueryParams } from '../domain/security-event.types';
import { ISecurityEventRepository } from '../domain/security-event.repository.interface';

export class InMemorySecurityEventRepository implements ISecurityEventRepository {
  private events: Map<string, SecurityEvent> = new Map();

  async save(event: SecurityEvent): Promise<void> {
    this.events.set(event.id, event);
  }

  async saveBatch(events: SecurityEvent[]): Promise<void> {
    for (const e of events) {
      this.events.set(e.id, e);
    }
  }

  async findById(tenantId: string, eventId: string): Promise<SecurityEvent | null> {
    const e = this.events.get(eventId);
    if (e && e.tenantId === tenantId) {
      return e;
    }
    return null;
  }

  async query(
    tenantId: string,
    params: SecurityEventQueryParams,
  ): Promise<{ items: SecurityEvent[]; total: number }> {
    let matches = Array.from(this.events.values()).filter((e) => e.tenantId === tenantId);

    if (params.siteId) {
      matches = matches.filter((e) => e.siteId === params.siteId);
    }
    if (params.action) {
      matches = matches.filter((e) => e.action === params.action);
    }
    if (params.minRiskScore !== undefined) {
      matches = matches.filter((e) => e.riskScore >= params.minRiskScore!);
    }
    if (params.maxRiskScore !== undefined) {
      matches = matches.filter((e) => e.riskScore <= params.maxRiskScore!);
    }
    if (params.stageUsed) {
      matches = matches.filter((e) => e.stageUsed === params.stageUsed);
    }
    if (params.degradedMode !== undefined) {
      matches = matches.filter((e) => e.degradedMode === params.degradedMode);
    }
    if (params.pathContains) {
      const needle = params.pathContains.toLowerCase();
      matches = matches.filter((e) => e.path.toLowerCase().includes(needle));
    }
    if (params.from) {
      matches = matches.filter((e) => e.createdAt >= params.from!);
    }
    if (params.to) {
      matches = matches.filter((e) => e.createdAt <= params.to!);
    }

    // Sort descending by createdAt
    matches.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    const total = matches.length;
    const page = Math.max(1, params.page ?? 1);
    const limit = Math.min(100, Math.max(1, params.limit ?? 20));
    const offset = (page - 1) * limit;

    const items = matches.slice(offset, offset + limit);
    return { items, total };
  }

  async findRawForAnalytics(
    tenantId: string,
    options: {
      siteId?: string;
      from?: Date;
      to?: Date;
      limit?: number;
    },
  ): Promise<SecurityEvent[]> {
    let matches = Array.from(this.events.values()).filter((e) => e.tenantId === tenantId);

    if (options.siteId) {
      matches = matches.filter((e) => e.siteId === options.siteId);
    }
    if (options.from) {
      matches = matches.filter((e) => e.createdAt >= options.from!);
    }
    if (options.to) {
      matches = matches.filter((e) => e.createdAt <= options.to!);
    }

    matches.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

    if (options.limit) {
      matches = matches.slice(0, options.limit);
    }
    return matches;
  }

  clear(): void {
    this.events.clear();
  }
}
