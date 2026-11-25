import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import {
  IWebhookEndpointRepository,
  WEBHOOK_ENDPOINT_REPOSITORY,
} from '../../domain/repositories/webhook-endpoint.repository.interface';
import { WebhookEndpoint } from '../../domain/webhook-endpoint.entity';

@Injectable()
export class ListWebhooksUseCase {
  constructor(
    @Inject(WEBHOOK_ENDPOINT_REPOSITORY)
    private readonly webhookRepo: IWebhookEndpointRepository,
  ) {}

  async execute(tenantId: string): Promise<
    {
      id: string;
      name: string;
      url: string;
      events: string[];
      isActive: boolean;
      createdAt: Date;
      updatedAt: Date;
    }[]
  > {
    const endpoints = await this.webhookRepo.findAllByTenant(tenantId);
    return endpoints.map((ep) => ({
      id: ep.id,
      name: ep.name,
      url: ep.url.value,
      events: ep.events,
      isActive: ep.isActive,
      createdAt: ep.createdAt,
      updatedAt: ep.updatedAt,
    }));
  }
}

@Injectable()
export class DeleteWebhookUseCase {
  constructor(
    @Inject(WEBHOOK_ENDPOINT_REPOSITORY)
    private readonly webhookRepo: IWebhookEndpointRepository,
  ) {}

  async execute(id: string, tenantId: string): Promise<void> {
    const existing = await this.webhookRepo.findById(id, tenantId);
    if (!existing) {
      throw new NotFoundException(`Webhook endpoint with ID ${id} not found`);
    }
    await this.webhookRepo.delete(id, tenantId);
  }
}
