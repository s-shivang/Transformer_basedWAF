import { Module } from '@nestjs/common';
import { TenantsController } from './presentation/tenants.controller';
import { CreateTenantUseCase } from './application/create-tenant.use-case';
import { GetTenantByIdUseCase } from './application/get-tenant-by-id.use-case';
import { GetTenantBySlugUseCase } from './application/get-tenant-by-slug.use-case';
import { ListTenantsUseCase } from './application/list-tenants.use-case';
import { TENANT_REPOSITORY } from './domain/tenant.repository.interface';
import { PrismaTenantRepository } from './infrastructure/prisma-tenant.repository';
import { PrismaService } from '@shared/infrastructure/prisma.service';

@Module({
  controllers: [TenantsController],
  providers: [
    CreateTenantUseCase,
    GetTenantByIdUseCase,
    GetTenantBySlugUseCase,
    ListTenantsUseCase,
    PrismaService,
    {
      provide: TENANT_REPOSITORY,
      useClass: PrismaTenantRepository,
    },
  ],
  exports: [TENANT_REPOSITORY, GetTenantByIdUseCase],
})
export class TenantsModule {}
