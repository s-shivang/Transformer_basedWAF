import { Module, forwardRef } from '@nestjs/common';
import { ProtectedSitesController } from './presentation/protected-sites.controller';
import {
  CreateProtectedSiteUseCase,
  ListProtectedSitesUseCase,
  GetProtectedSiteUseCase,
  UpdateProtectedSiteUseCase,
  DeleteProtectedSiteUseCase,
} from './application/protected-site.use-cases';
import { PROTECTED_SITE_REPOSITORY } from './domain/protected-site.repository.interface';
import { PrismaProtectedSiteRepository } from './infrastructure/prisma-protected-site.repository';
import { WafPoliciesModule } from '../waf-policies/waf-policies.module';
import { IdentityModule } from '../identity/identity.module';
import { PrismaService } from '@shared/infrastructure/prisma.service';

@Module({
  imports: [
    forwardRef(() => WafPoliciesModule),
    forwardRef(() => IdentityModule),
  ],
  controllers: [ProtectedSitesController],
  providers: [
    CreateProtectedSiteUseCase,
    ListProtectedSitesUseCase,
    GetProtectedSiteUseCase,
    UpdateProtectedSiteUseCase,
    DeleteProtectedSiteUseCase,
    PrismaService,
    {
      provide: PROTECTED_SITE_REPOSITORY,
      useClass: PrismaProtectedSiteRepository,
    },
  ],
  exports: [
    PROTECTED_SITE_REPOSITORY,
    CreateProtectedSiteUseCase,
    ListProtectedSitesUseCase,
    GetProtectedSiteUseCase,
    UpdateProtectedSiteUseCase,
    DeleteProtectedSiteUseCase,
  ],
})
export class ProtectedSitesModule {}
