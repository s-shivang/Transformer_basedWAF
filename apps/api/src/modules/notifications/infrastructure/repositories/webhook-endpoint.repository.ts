import { Injectable } from '@nestjs/common';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import { IWebhookEndpointRepository } from '../../domain/repositories/webhook-endpoint.repository.interface';
import { WebhookEndpoint } from '../../domain/webhook-endpoint.entity';
import { WebhookUrl } from '../../domain/webhook-url.value-object';

@Injectable()
export class PrismaWebhookEndpointRepository implements IWebhookEndpointRepository {
  constructor(private readonly prisma: PrismaService) {}

  async save(endpoint: WebhookEndpoint): Promise<void> {
    await this.prisma.webhookEndpoint.upsert({
      where: { id: endpoint.id },
      create: {
        id: endpoint.id,
        tenantId: endpoint.tenantId,
        name: endpoint.name,
        url: endpoint.url.value,
        secretHash: endpoint.secretHash,
        eventsJson: endpoint.events as any,
        isActive: endpoint.isActive,
        createdAt: endpoint.createdAt,
        updatedAt: endpoint.updatedAt,
      },
      update: {
        name: endpoint.name,
        url: endpoint.url.value,
        eventsJson: endpoint.events as any,
        isActive: endpoint.isActive,
        updatedAt: new Date(),
      },
    });
  }

  async findById(id: string, tenantId: string): Promise<WebhookEndpoint | null> {
    const raw = await this.prisma.webhookEndpoint.findFirst({
      where: { id, tenantId },
    });
    if (!raw) return null;
    return this.mapToEntity(raw);
  }

  async findActiveByTenant(tenantId: string): Promise<WebhookEndpoint[]> {
    const list = await this.prisma.webhookEndpoint.findMany({
      where: { tenantId, isActive: true },
      orderBy: { createdAt: 'asc' },
    });
    return list.map((r) => this.mapToEntity(r));
  }

  async findAllByTenant(tenantId: string): Promise<WebhookEndpoint[]> {
    const list = await this.prisma.webhookEndpoint.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' },
    });
    return list.map((r) => this.mapToEntity(r));
  }

  async delete(id: string, tenantId: string): Promise<void> {
    await this.prisma.webhookEndpoint.deleteMany({
      where: { id, tenantId },
    });
  }

  private mapToEntity(raw: any): WebhookEndpoint {
    return new WebhookEndpoint(raw.id, {
      tenantId: raw.tenantId,
      name: raw.name,
      url: WebhookUrl.create(raw.url),
      secretHash: raw.secretHash,
      events: Array.isArray(raw.eventsJson) ? (raw.eventsJson as string[]) : [],
      isActive: raw.isActive,
      createdAt: raw.createdAt,
      updatedAt: raw.updatedAt,
    });
  }
}

export class InMemoryWebhookEndpointRepository implements IWebhookEndpointRepository {
  private endpoints = new Map<string, WebhookEndpoint>();

  async save(endpoint: WebhookEndpoint): Promise<void> {
    this.endpoints.set(endpoint.id, endpoint);
  }

  async findById(id: string, tenantId: string): Promise<WebhookEndpoint | null> {
    const found = this.endpoints.get(id);
    if (!found || found.tenantId !== tenantId) return null;
    return found;
  }

  async findActiveByTenant(tenantId: string): Promise<WebhookEndpoint[]> {
    return Array.from(this.endpoints.values()).filter(
      (ep) => ep.tenantId === tenantId && ep.isActive,
    );
  }

  async findAllByTenant(tenantId: string): Promise<WebhookEndpoint[]> {
    return Array.from(this.endpoints.values()).filter(
      (ep) => ep.tenantId === tenantId,
    );
  }

  async delete(id: string, tenantId: string): Promise<void> {
    const found = await this.findById(id, tenantId);
    if (found) {
      this.endpoints.delete(id);
    }
  }

  clear() {
    this.endpoints.clear();
  }
}
