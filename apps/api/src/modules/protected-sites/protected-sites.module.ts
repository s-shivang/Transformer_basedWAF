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
  RetrySiteOnboardingUseCase,
  PauseResumeSiteUseCase,
} from './application/protected-site-onboarding.use-cases';
import { PROTECTED_SITE_REPOSITORY } from './domain/protected-site.repository.interface';
import { PrismaProtectedSiteRepository } from './infrastructure/prisma-protected-site.repository';
import { DNS_VERIFIER } from './domain/dns-verifier.interface';
import { NodeDnsVerifier } from './infrastructure/dns/node-dns.verifier';
import { LocalDevDnsVerifier } from './infrastructure/dns/local-dev-dns.verifier';
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
    LocalDevDnsVerifier,
    NodeDnsVerifier,
  ],
  exports: [
    PROTECTED_SITE_REPOSITORY,
    DNS_VERIFIER,
    CreateProtectedSiteUseCase,
    ListProtectedSitesUseCase,
    GetProtectedSiteUseCase,
    UpdateProtectedSiteUseCase,
    DeleteProtectedSiteUseCase,
    StartSiteOnboardingUseCase,
    GetOnboardingInstructionsUseCase,
    VerifySiteDomainUseCase,
    RetrySiteOnboardingUseCase,
    PauseResumeSiteUseCase,
    LocalDevDnsVerifier,
  ],
})
export class ProtectedSitesModule {}
