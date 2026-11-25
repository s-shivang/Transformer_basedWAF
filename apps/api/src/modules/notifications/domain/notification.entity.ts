import { Entity } from '@shared/domain/entity.base';
import { NotificationSeverity, NotificationType } from './notification-types';

export interface NotificationProps {
  tenantId: string;
  siteId?: string | null;
  severity: NotificationSeverity;
  type: NotificationType;
  title: string;
  message: string;
  metadataJson?: Record<string, any> | null;
  isRead: boolean;
  readAt?: Date | null;
  createdAt: Date;
}

export class Notification extends Entity<string> {
  private props: NotificationProps;

  constructor(id: string, props: NotificationProps) {
    super(id);
    this.props = {
      ...props,
      metadataJson: props.metadataJson || null,
      readAt: props.readAt || null,
    };
  }

  public static create(
    id: string,
    params: {
      tenantId: string;
      siteId?: string | null;
      severity: NotificationSeverity;
      type: NotificationType;
      title: string;
      message: string;
      metadataJson?: Record<string, any> | null;
    },
  ): Notification {
    if (!params.tenantId) throw new Error('Tenant ID is required for notification');
    if (!params.title) throw new Error('Title is required for notification');
    if (!params.message) throw new Error('Message is required for notification');

    return new Notification(id, {
      ...params,
      isRead: false,
      readAt: null,
      createdAt: new Date(),
    });
  }

  get tenantId(): string {
    return this.props.tenantId;
  }

  get siteId(): string | null | undefined {
    return this.props.siteId;
  }

  get severity(): NotificationSeverity {
    return this.props.severity;
  }

  get type(): NotificationType {
    return this.props.type;
  }

  get title(): string {
    return this.props.title;
  }

  get message(): string {
    return this.props.message;
  }

  get metadataJson(): Record<string, any> | null | undefined {
    return this.props.metadataJson;
  }

  get isRead(): boolean {
    return this.props.isRead;
  }

  get readAt(): Date | null | undefined {
    return this.props.readAt;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  public markAsRead(): void {
    this.props.isRead = true;
    this.props.readAt = new Date();
  }
}
