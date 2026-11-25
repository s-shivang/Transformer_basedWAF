import { Inject, Injectable } from '@nestjs/common';
import {
  INotificationRepository,
  NOTIFICATION_REPOSITORY,
} from '../../domain/repositories/notification.repository.interface';
import { Notification } from '../../domain/notification.entity';

@Injectable()
export class GetNotificationsUseCase {
  constructor(
    @Inject(NOTIFICATION_REPOSITORY)
    private readonly notificationRepo: INotificationRepository,
  ) {}

  async execute(
    tenantId: string,
    filter?: { isRead?: boolean; limit?: number; offset?: number },
  ): Promise<{ notifications: Notification[]; total: number }> {
    return this.notificationRepo.findMany(tenantId, filter);
  }
}
