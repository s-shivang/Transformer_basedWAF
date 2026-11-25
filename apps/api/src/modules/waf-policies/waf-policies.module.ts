import { Module, forwardRef } from '@nestjs/common';
import { WafPoliciesController } from './presentation/waf-policies.controller';
import {
  GetSitePolicyUseCase,
  ListSitePolicyHistoryUseCase,
  UpdateSitePolicyUseCase,
  RollbackSitePolicyUseCase,
  GetEffectiveGatewayPolicyUseCase,
} from './application/waf-policy.use-cases';
import { WAF_POLICY_REPOSITORY } from './domain/waf-policy.repository.interface';
import { PrismaWafPolicyRepository } from './infrastructure/prisma-waf-policy.repository';
import { ProtectedSitesModule } from '../protected-sites/protected-sites.module';
import { IdentityModule } from '../identity/identity.module';
import { PrismaService } from '@shared/infrastructure/prisma.service';

@Module({
  imports: [
    forwardRef(() => ProtectedSitesModule),
    forwardRef(() => IdentityModule),
  ],
  controllers: [WafPoliciesController],
  providers: [
    GetSitePolicyUseCase,
    ListSitePolicyHistoryUseCase,
    UpdateSitePolicyUseCase,
    RollbackSitePolicyUseCase,
    GetEffectiveGatewayPolicyUseCase,
    PrismaService,
    {
      provide: WAF_POLICY_REPOSITORY,
      useClass: PrismaWafPolicyRepository,
    },
  ],
  exports: [
    WAF_POLICY_REPOSITORY,
    GetSitePolicyUseCase,
    ListSitePolicyHistoryUseCase,
    UpdateSitePolicyUseCase,
    RollbackSitePolicyUseCase,
    GetEffectiveGatewayPolicyUseCase,
  ],
})
export class WafPoliciesModule {}
