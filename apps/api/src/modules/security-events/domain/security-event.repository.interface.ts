import { SecurityEvent } from './security-event.entity';
import { SecurityEventQueryParams } from './security-event.types';

export const SECURITY_EVENT_REPOSITORY = Symbol('ISecurityEventRepository');

export interface ISecurityEventRepository {
  save(event: SecurityEvent): Promise<void>;
  saveBatch(events: SecurityEvent[]): Promise<void>;
  findById(tenantId: string, eventId: string): Promise<SecurityEvent | null>;
  findByIds(tenantId: string, eventIds: string[]): Promise<SecurityEvent[]>;
  query(tenantId: string, params: SecurityEventQueryParams): Promise<{ items: SecurityEvent[]; total: number }>;
  findRawForAnalytics(
    tenantId: string,
    options: {
      siteId?: string;
      from?: Date;
      to?: Date;
      limit?: number;
    },
  ): Promise<SecurityEvent[]>;
}
