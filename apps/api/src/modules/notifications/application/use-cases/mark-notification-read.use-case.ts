import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import {
  INotificationRepository,
  NOTIFICATION_REPOSITORY,
} from '../../domain/repositories/notification.repository.interface';
import { Notification } from '../../domain/notification.entity';

@Injectable()
export class MarkNotificationReadUseCase {
  constructor(
    @Inject(NOTIFICATION_REPOSITORY)
    private readonly notificationRepo: INotificationRepository,
  ) {}

  async execute(id: string, tenantId: string): Promise<Notification> {
    const notification = await this.notificationRepo.findById(id, tenantId);
    if (!notification) {
      throw new NotFoundException(`Notification with ID ${id} not found`);
    }

    notification.markAsRead();
    await this.notificationRepo.update(notification);
    return notification;
  }
}
