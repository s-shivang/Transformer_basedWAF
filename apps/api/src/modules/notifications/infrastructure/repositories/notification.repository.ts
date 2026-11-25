import { Injectable } from '@nestjs/common';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import {
  INotificationRepository,
  NotificationFilter,
} from '../../domain/repositories/notification.repository.interface';
import { Notification } from '../../domain/notification.entity';
import { NotificationSeverity, NotificationType } from '../../domain/notification-types';

@Injectable()
export class PrismaNotificationRepository implements INotificationRepository {
  constructor(private readonly prisma: PrismaService) {}

  async save(notification: Notification): Promise<void> {
    await this.prisma.notification.create({
      data: {
        id: notification.id,
        tenantId: notification.tenantId,
        siteId: notification.siteId || null,
        severity: notification.severity as any,
        type: notification.type as any,
        title: notification.title,
        message: notification.message,
        metadataJson: (notification.metadataJson as any) || undefined,
        isRead: notification.isRead,
        readAt: notification.readAt || null,
        createdAt: notification.createdAt,
      },
    });
  }

  async findById(id: string, tenantId: string): Promise<Notification | null> {
    const raw = await this.prisma.notification.findFirst({
      where: { id, tenantId },
    });
    if (!raw) return null;
    return this.mapToEntity(raw);
  }

  async findMany(
    tenantId: string,
    filter?: NotificationFilter,
  ): Promise<{ notifications: Notification[]; total: number }> {
    const where: any = { tenantId };
    if (filter?.isRead !== undefined) {
      where.isRead = filter.isRead;
    }

    const [rawList, total] = await Promise.all([
      this.prisma.notification.findMany({
        where,
        take: filter?.limit || 50,
        skip: filter?.offset || 0,
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.notification.count({ where }),
    ]);

    return {
      notifications: rawList.map((r) => this.mapToEntity(r)),
      total,
    };
  }

  async update(notification: Notification): Promise<void> {
    await this.prisma.notification.updateMany({
      where: { id: notification.id, tenantId: notification.tenantId },
      data: {
        isRead: notification.isRead,
        readAt: notification.readAt || null,
      },
    });
  }

  private mapToEntity(raw: any): Notification {
    return new Notification(raw.id, {
      tenantId: raw.tenantId,
      siteId: raw.siteId,
      severity: raw.severity as NotificationSeverity,
      type: raw.type as NotificationType,
      title: raw.title,
      message: raw.message,
      metadataJson: raw.metadataJson as Record<string, any>,
      isRead: raw.isRead,
      readAt: raw.readAt,
      createdAt: raw.createdAt,
    });
  }
}

export class InMemoryNotificationRepository implements INotificationRepository {
  private notifications = new Map<string, Notification>();

  async save(notification: Notification): Promise<void> {
    this.notifications.set(notification.id, notification);
  }

  async findById(id: string, tenantId: string): Promise<Notification | null> {
    const found = this.notifications.get(id);
    if (!found || found.tenantId !== tenantId) return null;
    return found;
  }

  async findMany(
    tenantId: string,
    filter?: NotificationFilter,
  ): Promise<{ notifications: Notification[]; total: number }> {
    let list = Array.from(this.notifications.values()).filter(
      (n) => n.tenantId === tenantId,
    );

    if (filter?.isRead !== undefined) {
      list = list.filter((n) => n.isRead === filter.isRead);
    }

    list.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    const total = list.length;
    const offset = filter?.offset || 0;
    const limit = filter?.limit || 50;
    const paged = list.slice(offset, offset + limit);

    return { notifications: paged, total };
  }

  async update(notification: Notification): Promise<void> {
    const existing = await this.findById(notification.id, notification.tenantId);
    if (existing) {
      this.notifications.set(notification.id, notification);
    }
  }

  clear() {
    this.notifications.clear();
  }
}
