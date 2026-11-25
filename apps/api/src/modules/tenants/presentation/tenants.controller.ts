import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  HttpStatus,
  HttpException,
  UseGuards,
  Req,
} from '@nestjs/common';
import { Request } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { CreateTenantUseCase } from '../application/create-tenant.use-case';
import { GetTenantByIdUseCase } from '../application/get-tenant-by-id.use-case';
import { GetTenantBySlugUseCase } from '../application/get-tenant-by-slug.use-case';
import { ListTenantsUseCase } from '../application/list-tenants.use-case';
import { UpdateTenantQuotaUseCase } from '../application/update-tenant-quota.use-case';
import { CreateTenantRequestDto } from './dtos/create-tenant.request.dto';
import { TenantResponseDto, UpdateTenantQuotaDto } from '../application/dtos/tenant.dto';
import { JwtAuthGuard } from '../../identity/presentation/guards/jwt-auth.guard';
import { TenantScopeGuard } from '../../identity/presentation/guards/tenant-scope.guard';
import { RolesGuard } from '../../identity/presentation/guards/roles.guard';
import { Roles } from '../../identity/presentation/guards/roles.decorator';
import { UserRole } from '../../identity/domain/user-role';

@ApiTags('Tenants')
@Controller('tenants')
export class TenantsController {
  constructor(
    private readonly createTenantUseCase: CreateTenantUseCase,
    private readonly getTenantByIdUseCase: GetTenantByIdUseCase,
    private readonly getTenantBySlugUseCase: GetTenantBySlugUseCase,
    private readonly listTenantsUseCase: ListTenantsUseCase,
    private readonly updateQuotaUseCase: UpdateTenantQuotaUseCase,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Create a new tenant' })
  @ApiResponse({ status: 201, description: 'Tenant successfully created' })
  @ApiResponse({ status: 400, description: 'Validation failed or duplicate slug' })
  async create(@Body() body: CreateTenantRequestDto): Promise<TenantResponseDto> {
    const result = await this.createTenantUseCase.execute(body);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.BAD_REQUEST);
    }
    return result.getValue();
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'List tenant for the authenticated user' })
  @ApiResponse({ status: 200, description: 'List user active tenant' })
  async findAll(@Req() req: Request): Promise<TenantResponseDto[]> {
    const activeTenantId = req.tenantContext?.tenantId;
    if (!activeTenantId) {
      return [];
    }
    const result = await this.getTenantByIdUseCase.execute(activeTenantId);
    if (result.isFailure) {
      return [];
    }
    return [result.getValue()];
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard, TenantScopeGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get a tenant by UUID (Scoped to caller tenant)' })
  @ApiResponse({ status: 200, description: 'Tenant found' })
  @ApiResponse({ status: 403, description: 'Forbidden (Cross-tenant access)' })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  async findById(@Param('id') id: string): Promise<TenantResponseDto> {
    const result = await this.getTenantByIdUseCase.execute(id);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }
    return result.getValue();
  }

  @Patch(':id/quota')
  @UseGuards(JwtAuthGuard, TenantScopeGuard, RolesGuard)
  @Roles(UserRole.OWNER)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update tenant max protected site quota (OWNER only)' })
  @ApiResponse({ status: 200, description: 'Tenant quota updated successfully' })
  @ApiResponse({ status: 400, description: 'Invalid quota limit' })
  @ApiResponse({ status: 403, description: 'Forbidden: Requires OWNER role' })
  async updateQuota(
    @Param('id') id: string,
    @Body() body: UpdateTenantQuotaDto,
    @Req() req: Request,
  ): Promise<TenantResponseDto> {
    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.updateQuotaUseCase.execute(id, body, userId, clientIp);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.BAD_REQUEST);
    }
    return result.getValue();
  }

  @Get('slug/:slug')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get a tenant by unique slug (Scoped to caller tenant)' })
  @ApiResponse({ status: 200, description: 'Tenant found' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  async findBySlug(@Param('slug') slug: string, @Req() req: Request): Promise<TenantResponseDto> {
    const result = await this.getTenantBySlugUseCase.execute(slug);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }
    const tenant = result.getValue();
    if (req.tenantContext && tenant.id !== req.tenantContext.tenantId) {
      throw new HttpException('Access to requested tenant is forbidden', HttpStatus.FORBIDDEN);
    }
    return tenant;
  }
}
