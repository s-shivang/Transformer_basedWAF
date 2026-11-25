import { Module } from '@nestjs/common';
import { HealthController } from '@shared/infrastructure/health.controller';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import { TenantsModule } from './modules/tenants/tenants.module';
import { IdentityModule } from './modules/identity/identity.module';
import { ProtectedSitesModule } from './modules/protected-sites/protected-sites.module';
import { WafPoliciesModule } from './modules/waf-policies/waf-policies.module';
import { SecurityEventsModule } from './modules/security-events/security-events.module';
import { AnalyticsModule } from './modules/analytics/analytics.module';

@Module({
  imports: [
    TenantsModule,
    IdentityModule,
    ProtectedSitesModule,
    WafPoliciesModule,
    SecurityEventsModule,
    AnalyticsModule,
  ],
  controllers: [HealthController],
  providers: [PrismaService],
})
export class AppModule {}
