import { WebhookEndpoint } from '../webhook-endpoint.entity';

export interface IWebhookEndpointRepository {
  save(endpoint: WebhookEndpoint): Promise<void>;
  findById(id: string, tenantId: string): Promise<WebhookEndpoint | null>;
  findActiveByTenant(tenantId: string): Promise<WebhookEndpoint[]>;
  findAllByTenant(tenantId: string): Promise<WebhookEndpoint[]>;
  delete(id: string, tenantId: string): Promise<void>;
}

export const WEBHOOK_ENDPOINT_REPOSITORY = 'WEBHOOK_ENDPOINT_REPOSITORY';
