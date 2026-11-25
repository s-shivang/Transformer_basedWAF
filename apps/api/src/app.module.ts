import { Module } from '@nestjs/common';
import { HealthController } from '@shared/infrastructure/health.controller';
import { PrismaService } from '@shared/infrastructure/prisma.service';
import { QueuesModule } from '@shared/infrastructure/queues/queues.module';
import { TenantsModule } from './modules/tenants/tenants.module';
import { IdentityModule } from './modules/identity/identity.module';
import { ProtectedSitesModule } from './modules/protected-sites/protected-sites.module';
import { WafPoliciesModule } from './modules/waf-policies/waf-policies.module';
import { SecurityEventsModule } from './modules/security-events/security-events.module';
import { AnalyticsModule } from './modules/analytics/analytics.module';
import { NotificationsModule } from './modules/notifications/notifications.module';

@Module({
  imports: [
    QueuesModule,
    TenantsModule,
    IdentityModule,
    ProtectedSitesModule,
    WafPoliciesModule,
    SecurityEventsModule,
    AnalyticsModule,
    NotificationsModule,
  ],
  controllers: [HealthController],
  providers: [PrismaService],
})
export class AppModule {}
