import { Notification } from '../notification.entity';

export interface NotificationFilter {
  isRead?: boolean;
  limit?: number;
  offset?: number;
}

export interface INotificationRepository {
  save(notification: Notification): Promise<void>;
  findById(id: string, tenantId: string): Promise<Notification | null>;
  findMany(
    tenantId: string,
    filter?: NotificationFilter,
  ): Promise<{ notifications: Notification[]; total: number }>;
  update(notification: Notification): Promise<void>;
}

export const NOTIFICATION_REPOSITORY = 'NOTIFICATION_REPOSITORY';
