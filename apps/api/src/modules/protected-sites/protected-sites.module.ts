import { Module, forwardRef } from '@nestjs/common';
import { ProtectedSitesController } from './presentation/protected-sites.controller';
import {
  CreateProtectedSiteUseCase,
  ListProtectedSitesUseCase,
  GetProtectedSiteUseCase,
  UpdateProtectedSiteUseCase,
  DeleteProtectedSiteUseCase,
} from './application/protected-site.use-cases';
import {
  StartSiteOnboardingUseCase,
  GetOnboardingInstructionsUseCase,
  VerifySiteDomainUseCase,
  ConfigureSiteOnGatewayUseCase,
  RetrySiteOnboardingUseCase,
  PauseResumeSiteUseCase,
} from './application/protected-site-onboarding.use-cases';
import { PROTECTED_SITE_REPOSITORY } from './domain/protected-site.repository.interface';
import { PrismaProtectedSiteRepository } from './infrastructure/prisma-protected-site.repository';
import { DNS_VERIFIER } from './domain/dns-verifier.interface';
import { NodeDnsVerifier } from './infrastructure/dns/node-dns.verifier';
import { LocalDevDnsVerifier } from './infrastructure/dns/local-dev-dns.verifier';
import { SITE_CONFIG_SYNC_CLIENT } from './domain/site-config-sync.interface';
import { HttpSiteConfigSyncClient } from './infrastructure/gateway/http-site-config-sync.client';
import { InMemorySiteConfigSyncClient } from './infrastructure/gateway/in-memory-site-config-sync.client';
import { WafPoliciesModule } from '../waf-policies/waf-policies.module';
import { IdentityModule } from '../identity/identity.module';
import { TenantsModule } from '../tenants/tenants.module';
import { PrismaService } from '@shared/infrastructure/prisma.service';

@Module({
  imports: [
    forwardRef(() => WafPoliciesModule),
    forwardRef(() => IdentityModule),
    forwardRef(() => TenantsModule),
  ],
  controllers: [ProtectedSitesController],
  providers: [
    CreateProtectedSiteUseCase,
    ListProtectedSitesUseCase,
    GetProtectedSiteUseCase,
    UpdateProtectedSiteUseCase,
    DeleteProtectedSiteUseCase,
    StartSiteOnboardingUseCase,
    GetOnboardingInstructionsUseCase,
    VerifySiteDomainUseCase,
    ConfigureSiteOnGatewayUseCase,
    RetrySiteOnboardingUseCase,
    PauseResumeSiteUseCase,
    PrismaService,
    {
      provide: PROTECTED_SITE_REPOSITORY,
      useClass: PrismaProtectedSiteRepository,
    },
    {
      provide: DNS_VERIFIER,
      useClass:
        process.env.NODE_ENV === 'test' || process.env.WAF_LOCAL_DEV_DNS === 'true'
          ? LocalDevDnsVerifier
          : NodeDnsVerifier,
    },
    {
      provide: SITE_CONFIG_SYNC_CLIENT,
      useClass:
        process.env.NODE_ENV === 'test' || process.env.WAF_LOCAL_DEV_DNS === 'true'
          ? InMemorySiteConfigSyncClient
          : HttpSiteConfigSyncClient,
    },
    LocalDevDnsVerifier,
    NodeDnsVerifier,
    InMemorySiteConfigSyncClient,
    HttpSiteConfigSyncClient,
  ],
  exports: [
    PROTECTED_SITE_REPOSITORY,
    DNS_VERIFIER,
    SITE_CONFIG_SYNC_CLIENT,
    CreateProtectedSiteUseCase,
    ListProtectedSitesUseCase,
    GetProtectedSiteUseCase,
    UpdateProtectedSiteUseCase,
    DeleteProtectedSiteUseCase,
    StartSiteOnboardingUseCase,
    GetOnboardingInstructionsUseCase,
    VerifySiteDomainUseCase,
    ConfigureSiteOnGatewayUseCase,
    RetrySiteOnboardingUseCase,
    PauseResumeSiteUseCase,
    LocalDevDnsVerifier,
    InMemorySiteConfigSyncClient,
  ],
})
export class ProtectedSitesModule {}
