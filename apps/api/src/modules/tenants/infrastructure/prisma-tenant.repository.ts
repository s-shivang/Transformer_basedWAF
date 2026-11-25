import { Injectable } from '@nestjs/common';
import {
  Tenant,
  TenantTier,
  TenantStatus,
} from '../domain/tenant.entity';
import { TenantId } from '../domain/tenant-id.vo';
import { TenantSlug } from '../domain/tenant-slug.vo';
import { ITenantRepository } from '../domain/tenant.repository.interface';
import { PrismaService } from '@shared/infrastructure/prisma.service';

@Injectable()
export class PrismaTenantRepository implements ITenantRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById(id: TenantId): Promise<Tenant | null> {
    const record = await this.prisma.tenant.findUnique({
      where: { id: id.value },
    });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findBySlug(slug: TenantSlug): Promise<Tenant | null> {
    const record = await this.prisma.tenant.findUnique({
      where: { slug: slug.value },
    });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findAll(): Promise<Tenant[]> {
    const records = await this.prisma.tenant.findMany({
      orderBy: { createdAt: 'desc' },
    });
    return records.map((r) => this.toDomain(r));
  }

  async save(tenant: Tenant): Promise<void> {
    await this.prisma.tenant.upsert({
      where: { id: tenant.id.value },
      create: {
        id: tenant.id.value,
        name: tenant.name,
        slug: tenant.slug.value,
        tier: tenant.tier as any,
        status: tenant.status as any,
        maxSites: tenant.maxSites,
        createdAt: tenant.createdAt,
        updatedAt: tenant.updatedAt,
      },
      update: {
        name: tenant.name,
        slug: tenant.slug.value,
        tier: tenant.tier as any,
        status: tenant.status as any,
        maxSites: tenant.maxSites,
        updatedAt: tenant.updatedAt,
      },
    });
  }

  async delete(id: TenantId): Promise<void> {
    await this.prisma.tenant.delete({
      where: { id: id.value },
    });
  }

  async exists(slug: TenantSlug): Promise<boolean> {
    const count = await this.prisma.tenant.count({
      where: { slug: slug.value },
    });
    return count > 0;
  }

  private toDomain(record: any): Tenant {
    return Tenant.reconstitute(
      TenantId.create(record.id).getValue(),
      {
        name: record.name,
        slug: TenantSlug.create(record.slug).getValue(),
        tier: record.tier as TenantTier,
        status: record.status as TenantStatus,
        maxSites: record.maxSites ?? 5,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      },
    );
  }
}
