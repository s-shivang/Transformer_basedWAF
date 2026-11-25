import { Module, forwardRef } from '@nestjs/common';
import { InternalEventsController } from './presentation/internal-events.controller';
import { SecurityEventsController } from './presentation/security-events.controller';
import { InternalIngestKeyGuard } from './presentation/guards/internal-ingest-key.guard';
import {
  IngestSecurityEventsUseCase,
  QuerySecurityEventsUseCase,
  GetSecurityEventByIdUseCase,
  SubmitEventFeedbackUseCase,
  ListFeedbackQueueUseCase,
  ReviewEventFeedbackUseCase,
} from './application/security-event.use-cases';
import { SECURITY_EVENT_REPOSITORY } from './domain/security-event.repository.interface';
import { EVENT_FEEDBACK_REPOSITORY } from './domain/event-feedback.repository.interface';
import { PrismaSecurityEventRepository } from './infrastructure/prisma-security-event.repository';
import { PrismaEventFeedbackRepository } from './infrastructure/prisma-event-feedback.repository';
import { ProtectedSitesModule } from '../protected-sites/protected-sites.module';
import { IdentityModule } from '../identity/identity.module';
import { PrismaService } from '@shared/infrastructure/prisma.service';

@Module({
  imports: [
    forwardRef(() => ProtectedSitesModule),
    forwardRef(() => IdentityModule),
  ],
  controllers: [InternalEventsController, SecurityEventsController],
  providers: [
    PrismaService,
    InternalIngestKeyGuard,
    IngestSecurityEventsUseCase,
    QuerySecurityEventsUseCase,
    GetSecurityEventByIdUseCase,
    SubmitEventFeedbackUseCase,
    ListFeedbackQueueUseCase,
    ReviewEventFeedbackUseCase,
    {
      provide: SECURITY_EVENT_REPOSITORY,
      useClass: PrismaSecurityEventRepository,
    },
    {
      provide: EVENT_FEEDBACK_REPOSITORY,
      useClass: PrismaEventFeedbackRepository,
    },
  ],
  exports: [
    SECURITY_EVENT_REPOSITORY,
    EVENT_FEEDBACK_REPOSITORY,
    IngestSecurityEventsUseCase,
    QuerySecurityEventsUseCase,
    GetSecurityEventByIdUseCase,
    SubmitEventFeedbackUseCase,
    ListFeedbackQueueUseCase,
    ReviewEventFeedbackUseCase,
  ],
})
export class SecurityEventsModule {}
