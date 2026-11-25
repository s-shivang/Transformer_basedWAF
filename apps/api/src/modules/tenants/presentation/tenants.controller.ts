import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { CreateTenantUseCase } from '../application/create-tenant.use-case';
import { GetTenantByIdUseCase } from '../application/get-tenant-by-id.use-case';
import { GetTenantBySlugUseCase } from '../application/get-tenant-by-slug.use-case';
import { ListTenantsUseCase } from '../application/list-tenants.use-case';
import { CreateTenantRequestDto } from './dtos/create-tenant.request.dto';
import { TenantResponseDto } from '../application/dtos/tenant.dto';

@ApiTags('Tenants')
@Controller('tenants')
export class TenantsController {
  constructor(
    private readonly createTenantUseCase: CreateTenantUseCase,
    private readonly getTenantByIdUseCase: GetTenantByIdUseCase,
    private readonly getTenantBySlugUseCase: GetTenantBySlugUseCase,
    private readonly listTenantsUseCase: ListTenantsUseCase,
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
  @ApiOperation({ summary: 'List all tenants' })
  @ApiResponse({ status: 200, description: 'List of all tenants' })
  async findAll(): Promise<TenantResponseDto[]> {
    const result = await this.listTenantsUseCase.execute();
    return result.getValue();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a tenant by UUID' })
  @ApiResponse({ status: 200, description: 'Tenant found' })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  async findById(@Param('id') id: string): Promise<TenantResponseDto> {
    const result = await this.getTenantByIdUseCase.execute(id);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }
    return result.getValue();
  }

  @Get('slug/:slug')
  @ApiOperation({ summary: 'Get a tenant by unique slug' })
  @ApiResponse({ status: 200, description: 'Tenant found' })
  @ApiResponse({ status: 404, description: 'Tenant not found' })
  async findBySlug(@Param('slug') slug: string): Promise<TenantResponseDto> {
    const result = await this.getTenantBySlugUseCase.execute(slug);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }
    return result.getValue();
  }
}
