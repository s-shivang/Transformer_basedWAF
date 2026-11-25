import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  HttpStatus,
  HttpException,
  UseGuards,
  Req,
} from '@nestjs/common';
import { Request } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import {
  CreateProtectedSiteUseCase,
  ListProtectedSitesUseCase,
  GetProtectedSiteUseCase,
  UpdateProtectedSiteUseCase,
  DeleteProtectedSiteUseCase,
} from '../application/protected-site.use-cases';
import {
  CreateProtectedSiteDto,
  UpdateProtectedSiteDto,
} from './dtos/protected-site.dto';
import { JwtAuthGuard } from '../../identity/presentation/guards/jwt-auth.guard';
import { RolesGuard } from '../../identity/presentation/guards/roles.guard';
import { Roles } from '../../identity/presentation/guards/roles.decorator';
import { UserRole } from '../../identity/domain/user-role';

@ApiTags('Protected Sites')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('sites')
export class ProtectedSitesController {
  constructor(
    private readonly createSiteUseCase: CreateProtectedSiteUseCase,
    private readonly listSitesUseCase: ListProtectedSitesUseCase,
    private readonly getSiteUseCase: GetProtectedSiteUseCase,
    private readonly updateSiteUseCase: UpdateProtectedSiteUseCase,
    private readonly deleteSiteUseCase: DeleteProtectedSiteUseCase,
  ) {}

  @Post()
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Register a new protected site and provision default v1 MONITOR policy' })
  @ApiResponse({ status: 201, description: 'Protected site registered successfully' })
  @ApiResponse({ status: 400, description: 'Validation failed or duplicate domain' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  async create(@Body() dto: CreateProtectedSiteDto, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.createSiteUseCase.execute(tenantId, dto, userId, clientIp);
    if (result.isFailure) {
      const err = result.getError();
      const status = err.includes('already exists') ? HttpStatus.CONFLICT : HttpStatus.BAD_REQUEST;
      throw new HttpException(err, status);
    }

    return result.getValue();
  }

  @Get()
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'List all protected sites for the authenticated tenant' })
  @ApiResponse({ status: 200, description: 'List of protected sites' })
  async list(@Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.listSitesUseCase.execute(tenantId);
    return result.getValue();
  }

  @Get(':siteId')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'Get details of a protected site' })
  @ApiResponse({ status: 200, description: 'Protected site details' })
  @ApiResponse({ status: 404, description: 'Protected site not found' })
  async get(@Param('siteId') siteId: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.getSiteUseCase.execute(tenantId, siteId);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }

    return result.getValue();
  }

  @Patch(':siteId')
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Update a protected site configuration' })
  @ApiResponse({ status: 200, description: 'Site updated successfully' })
  @ApiResponse({ status: 400, description: 'Validation failed' })
  @ApiResponse({ status: 404, description: 'Protected site not found' })
  async update(
    @Param('siteId') siteId: string,
    @Body() dto: UpdateProtectedSiteDto,
    @Req() req: Request,
  ) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.updateSiteUseCase.execute(tenantId, siteId, dto, userId, clientIp);
    if (result.isFailure) {
      const err = result.getError();
      const status = err.includes('not found') ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
      throw new HttpException(err, status);
    }

    return result.getValue();
  }

  @Delete(':siteId')
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Delete a protected site' })
  @ApiResponse({ status: 200, description: 'Site deleted successfully' })
  @ApiResponse({ status: 404, description: 'Protected site not found' })
  async delete(@Param('siteId') siteId: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.deleteSiteUseCase.execute(tenantId, siteId, userId, clientIp);
    if (result.isFailure) {
      const err = result.getError();
      const status = err.includes('not found') ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
      throw new HttpException(err, status);
    }

    return { success: true, message: 'Protected site deleted successfully' };
  }
}
