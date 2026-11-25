import { Injectable } from '@nestjs/common';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import { ProtectedSite, SiteStatus, OnboardingStatus } from '../domain/protected-site.entity';
import { SiteDomain } from '../domain/site-domain.vo';
import { OriginUrl } from '../domain/origin-url.vo';
import { IProtectedSiteRepository } from '../domain/protected-site.repository.interface';

@Injectable()
export class PrismaProtectedSiteRepository implements IProtectedSiteRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById(tenantId: string, siteId: string): Promise<ProtectedSite | null> {
    const record = await this.prisma.protectedSite.findFirst({
      where: { id: siteId, tenantId },
    });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findByDomain(tenantId: string, domain: SiteDomain): Promise<ProtectedSite | null> {
    const record = await this.prisma.protectedSite.findUnique({
      where: { domain: domain.value },
    });
    if (!record || record.tenantId !== tenantId) return null;
    return this.toDomain(record);
  }

  async findGlobalByDomain(domain: SiteDomain): Promise<ProtectedSite | null> {
    const record = await this.prisma.protectedSite.findUnique({
      where: { domain: domain.value },
    });
    if (!record) return null;
    return this.toDomain(record);
  }

  async findAllByTenant(tenantId: string): Promise<ProtectedSite[]> {
    const records = await this.prisma.protectedSite.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' },
    });
    return records.map((r) => this.toDomain(r));
  }

  async countByTenant(tenantId: string): Promise<number> {
    return this.prisma.protectedSite.count({
      where: { tenantId },
    });
  }

  async save(site: ProtectedSite): Promise<void> {
    await this.prisma.protectedSite.upsert({
      where: { id: site.id },
      create: {
        id: site.id,
        tenantId: site.tenantId,
        name: site.name,
        domain: site.domain.value,
        upstreamUrl: site.originUrl.value,
        status: site.status as any,
        onboardingStatus: site.onboardingStatus as any,
        verificationToken: site.verificationToken,
        verifiedAt: site.verifiedAt,
        configVersion: site.configVersion,
        lastOnboardingError: site.lastOnboardingError,
        createdAt: site.createdAt,
        updatedAt: site.updatedAt,
      },
      update: {
        name: site.name,
        upstreamUrl: site.originUrl.value,
        status: site.status as any,
        onboardingStatus: site.onboardingStatus as any,
        verificationToken: site.verificationToken,
        verifiedAt: site.verifiedAt,
        configVersion: site.configVersion,
        lastOnboardingError: site.lastOnboardingError,
        updatedAt: site.updatedAt,
      },
    });
  }

  async delete(tenantId: string, siteId: string): Promise<void> {
    await this.prisma.protectedSite.deleteMany({
      where: { id: siteId, tenantId },
    });
  }

  async exists(tenantId: string, domain: SiteDomain): Promise<boolean> {
    const count = await this.prisma.protectedSite.count({
      where: { tenantId, domain: domain.value },
    });
    return count > 0;
  }

  private toDomain(record: any): ProtectedSite {
    return ProtectedSite.reconstitute(record.id, {
      tenantId: record.tenantId,
      name: record.name,
      domain: SiteDomain.create(record.domain).getValue(),
      originUrl: OriginUrl.create(record.upstreamUrl).getValue(),
      status: record.status as SiteStatus,
      onboardingStatus: (record.onboardingStatus as OnboardingStatus) ?? OnboardingStatus.ACTIVE,
      verificationToken: record.verificationToken ?? null,
      verifiedAt: record.verifiedAt ?? null,
      configVersion: record.configVersion ?? 1,
      lastOnboardingError: record.lastOnboardingError ?? null,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    });
  }
}
