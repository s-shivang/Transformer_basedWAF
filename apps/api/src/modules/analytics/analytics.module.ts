import { Module, forwardRef } from '@nestjs/common';
import { AnalyticsController } from './presentation/analytics.controller';
import {
  GetAnalyticsOverviewUseCase,
  GetAnalyticsTimeseriesUseCase,
  GetTopThreatsUseCase,
} from './application/analytics.use-cases';
import { SecurityEventsModule } from '../security-events/security-events.module';
import { ProtectedSitesModule } from '../protected-sites/protected-sites.module';
import { IdentityModule } from '../identity/identity.module';

@Module({
  imports: [
    forwardRef(() => SecurityEventsModule),
    forwardRef(() => ProtectedSitesModule),
    forwardRef(() => IdentityModule),
  ],
  controllers: [AnalyticsController],
  providers: [
    GetAnalyticsOverviewUseCase,
    GetAnalyticsTimeseriesUseCase,
    GetTopThreatsUseCase,
  ],
  exports: [
    GetAnalyticsOverviewUseCase,
    GetAnalyticsTimeseriesUseCase,
    GetTopThreatsUseCase,
  ],
})
export class AnalyticsModule {}
