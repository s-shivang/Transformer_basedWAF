import { Inject, Injectable } from '@nestjs/common';
import * as crypto from 'crypto';
import {
  IWebhookEndpointRepository,
  WEBHOOK_ENDPOINT_REPOSITORY,
} from '../../domain/repositories/webhook-endpoint.repository.interface';
import { WebhookEndpoint } from '../../domain/webhook-endpoint.entity';
import { WebhookUrl } from '../../domain/webhook-url.value-object';

export interface CreateWebhookDto {
  name: string;
  url: string;
  events?: string[];
}

export interface CreatedWebhookResult {
  id: string;
  name: string;
  url: string;
  events: string[];
  isActive: boolean;
  secret: string; // Only returned once on creation
  createdAt: Date;
}

@Injectable()
export class CreateWebhookUseCase {
  constructor(
    @Inject(WEBHOOK_ENDPOINT_REPOSITORY)
    private readonly webhookRepo: IWebhookEndpointRepository,
  ) {}

  async execute(tenantId: string, dto: CreateWebhookDto): Promise<CreatedWebhookResult> {
    const webhookUrl = WebhookUrl.create(dto.url);
    const id = crypto.randomUUID();
    const rawSecret = `waf_whsec_${crypto.randomBytes(24).toString('hex')}`;

    const endpoint = WebhookEndpoint.create(id, {
      tenantId,
      name: dto.name,
      url: webhookUrl,
      secretHash: rawSecret, // stored secret used for HMAC-SHA256 signing
      events: dto.events,
    });

    await this.webhookRepo.save(endpoint);

    return {
      id: endpoint.id,
      name: endpoint.name,
      url: endpoint.url.value,
      events: endpoint.events,
      isActive: endpoint.isActive,
      secret: rawSecret,
      createdAt: endpoint.createdAt,
    };
  }
}
