import { Entity } from '@shared/domain/entity.base';
import { WebhookUrl } from './webhook-url.value-object';

export interface WebhookEndpointProps {
  tenantId: string;
  name: string;
  url: WebhookUrl;
  secretHash: string;
  events: string[];
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export class WebhookEndpoint extends Entity<string> {
  private props: WebhookEndpointProps;

  constructor(id: string, props: WebhookEndpointProps) {
    super(id);
    this.props = { ...props };
  }

  public static create(
    id: string,
    params: {
      tenantId: string;
      name: string;
      url: string | WebhookUrl;
      secretHash: string;
      events?: string[];
      isActive?: boolean;
    },
  ): WebhookEndpoint {
    if (!params.tenantId) throw new Error('Tenant ID is required for webhook endpoint');
    if (!params.name || params.name.trim().length === 0) {
      throw new Error('Name is required for webhook endpoint');
    }
    if (!params.secretHash) throw new Error('Secret hash is required for webhook endpoint');

    const webhookUrl =
      params.url instanceof WebhookUrl ? params.url : WebhookUrl.create(params.url);

    return new WebhookEndpoint(id, {
      tenantId: params.tenantId,
      name: params.name.trim(),
      url: webhookUrl,
      secretHash: params.secretHash,
      events: params.events || ['ATTACK_SPIKE', 'ML_DEGRADED', 'POLICY_SYNC_FAILED', 'FEEDBACK_EXPORT_READY'],
      isActive: params.isActive !== undefined ? params.isActive : true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  }

  get tenantId(): string {
    return this.props.tenantId;
  }

  get name(): string {
    return this.props.name;
  }

  get url(): WebhookUrl {
    return this.props.url;
  }

  get secretHash(): string {
    return this.props.secretHash;
  }

  get events(): string[] {
    return this.props.events;
  }

  get isActive(): boolean {
    return this.props.isActive;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  get updatedAt(): Date {
    return this.props.updatedAt;
  }

  public isSubscribedTo(eventType: string): boolean {
    return this.props.isActive && (this.props.events.includes(eventType) || this.props.events.includes('*'));
  }

  public deactivate(): void {
    this.props.isActive = false;
    this.props.updatedAt = new Date();
  }

  public activate(): void {
    this.props.isActive = true;
    this.props.updatedAt = new Date();
  }

  public updateEvents(events: string[]): void {
    this.props.events = events;
    this.props.updatedAt = new Date();
  }
}
