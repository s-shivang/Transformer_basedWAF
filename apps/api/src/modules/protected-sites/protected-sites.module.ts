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
  VerifyDnsRoutingUseCase,
  ProvisionSiteTlsUseCase,
  ActivateSiteUseCase,
  CheckSiteOriginHealthUseCase,
} from './application/protected-site-onboarding.use-cases';
import { PROTECTED_SITE_REPOSITORY } from './domain/protected-site.repository.interface';
import { PrismaProtectedSiteRepository } from './infrastructure/prisma-protected-site.repository';
import { DNS_VERIFIER } from './domain/dns-verifier.interface';
import { NodeDnsVerifier } from './infrastructure/dns/node-dns.verifier';
import { LocalDevDnsVerifier } from './infrastructure/dns/local-dev-dns.verifier';
import { SITE_CONFIG_SYNC_CLIENT } from './domain/site-config-sync.interface';
import { HttpSiteConfigSyncClient } from './infrastructure/gateway/http-site-config-sync.client';
import { InMemorySiteConfigSyncClient } from './infrastructure/gateway/in-memory-site-config-sync.client';
import { TLS_PROVISIONER } from './domain/tls-provisioner.interface';
import { LocalDevTlsProvisioner } from './infrastructure/tls/local-dev-tls.provisioner';
import { ORIGIN_HEALTH_CHECKER } from './domain/origin-health-checker.interface';
import { HttpOriginHealthChecker } from './infrastructure/health/http-origin-health.checker';
import { InMemoryOriginHealthChecker } from './infrastructure/health/in-memory-origin-health.checker';
import { WafPoliciesModule } from '../waf-policies/waf-policies.module';
import { IdentityModule } from '../identity/identity.module';
import { TenantsModule } from '../tenants/tenants.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { PrismaService } from '@shared/infrastructure/prisma.service';

@Module({
  imports: [
    forwardRef(() => WafPoliciesModule),
    forwardRef(() => IdentityModule),
    forwardRef(() => TenantsModule),
    forwardRef(() => NotificationsModule),
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
    VerifyDnsRoutingUseCase,
    ProvisionSiteTlsUseCase,
    ActivateSiteUseCase,
    CheckSiteOriginHealthUseCase,
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
        process.env.NODE_ENV === 'test' && process.env.WAF_USE_HTTP_SYNC !== 'true'
          ? InMemorySiteConfigSyncClient
          : HttpSiteConfigSyncClient,
    },
    {
      provide: TLS_PROVISIONER,
      useClass: LocalDevTlsProvisioner,
    },
    {
      provide: ORIGIN_HEALTH_CHECKER,
      useClass:
        process.env.NODE_ENV === 'test' && process.env.WAF_USE_HTTP_HEALTH !== 'true'
          ? InMemoryOriginHealthChecker
          : HttpOriginHealthChecker,
    },
    LocalDevDnsVerifier,
    NodeDnsVerifier,
    InMemorySiteConfigSyncClient,
    HttpSiteConfigSyncClient,
    LocalDevTlsProvisioner,
    HttpOriginHealthChecker,
    InMemoryOriginHealthChecker,
  ],
  exports: [
    PROTECTED_SITE_REPOSITORY,
    DNS_VERIFIER,
    SITE_CONFIG_SYNC_CLIENT,
    TLS_PROVISIONER,
    ORIGIN_HEALTH_CHECKER,
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
    VerifyDnsRoutingUseCase,
    ProvisionSiteTlsUseCase,
    ActivateSiteUseCase,
    CheckSiteOriginHealthUseCase,
    LocalDevDnsVerifier,
    InMemorySiteConfigSyncClient,
    LocalDevTlsProvisioner,
    HttpOriginHealthChecker,
    InMemoryOriginHealthChecker,
  ],
})
export class ProtectedSitesModule {}
