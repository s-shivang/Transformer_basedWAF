import {
  Controller,
  Get,
  Put,
  Post,
  Body,
  Param,
  HttpStatus,
  HttpCode,
  HttpException,
  UseGuards,
  Req,
} from '@nestjs/common';
import { Request } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import {
  GetSitePolicyUseCase,
  ListSitePolicyHistoryUseCase,
  UpdateSitePolicyUseCase,
  RollbackSitePolicyUseCase,
  GetEffectiveGatewayPolicyUseCase,
} from '../application/waf-policy.use-cases';
import { UpdateWafPolicyDto } from './dtos/waf-policy.dto';
import { JwtAuthGuard } from '../../identity/presentation/guards/jwt-auth.guard';
import { RolesGuard } from '../../identity/presentation/guards/roles.guard';
import { Roles } from '../../identity/presentation/guards/roles.decorator';
import { UserRole } from '../../identity/domain/user-role';

@ApiTags('WAF Policies')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('sites/:siteId/policy')
export class WafPoliciesController {
  constructor(
    private readonly getPolicyUseCase: GetSitePolicyUseCase,
    private readonly listHistoryUseCase: ListSitePolicyHistoryUseCase,
    private readonly updatePolicyUseCase: UpdateSitePolicyUseCase,
    private readonly rollbackPolicyUseCase: RollbackSitePolicyUseCase,
    private readonly getEffectiveUseCase: GetEffectiveGatewayPolicyUseCase,
  ) {}

  @Get()
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'Get the currently active WAF policy for a protected site' })
  @ApiResponse({ status: 200, description: 'Active WAF policy' })
  @ApiResponse({ status: 404, description: 'Site or active policy not found' })
  async getActive(@Param('siteId') siteId: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.getPolicyUseCase.execute(tenantId, siteId);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }

    return result.getValue();
  }

  @Get('history')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'List all historical policy versions for a site (audit trail)' })
  @ApiResponse({ status: 200, description: 'List of policy versions in reverse chronological order' })
  @ApiResponse({ status: 404, description: 'Site not found' })
  async getHistory(@Param('siteId') siteId: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.listHistoryUseCase.execute(tenantId, siteId);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }

    return result.getValue();
  }

  @Put()
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Update WAF policy creating an incremented active version' })
  @ApiResponse({ status: 200, description: 'New active policy version created' })
  @ApiResponse({ status: 400, description: 'Validation error in thresholds or exclusions' })
  @ApiResponse({ status: 404, description: 'Site not found' })
  async update(
    @Param('siteId') siteId: string,
    @Body() dto: UpdateWafPolicyDto,
    @Req() req: Request,
  ) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.updatePolicyUseCase.execute(tenantId, siteId, dto, userId, clientIp);
    if (result.isFailure) {
      const err = result.getError();
      const status = err.includes('not found') ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
      throw new HttpException(err, status);
    }

    return result.getValue();
  }

  @Post('rollback/:version')
  @HttpCode(HttpStatus.OK)
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: '1-click rollback: restore historical policy configuration as a new version' })
  @ApiResponse({ status: 200, description: 'Rollback policy version created successfully' })
  @ApiResponse({ status: 400, description: 'Invalid rollback request (e.g. target already active)' })
  @ApiResponse({ status: 404, description: 'Site or historical version not found' })
  async rollback(
    @Param('siteId') siteId: string,
    @Param('version') versionStr: string,
    @Req() req: Request,
  ) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const targetVersion = parseInt(versionStr, 10);
    if (isNaN(targetVersion) || targetVersion < 1) {
      throw new HttpException('Invalid policy version parameter', HttpStatus.BAD_REQUEST);
    }

    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.rollbackPolicyUseCase.execute(
      tenantId,
      siteId,
      targetVersion,
      userId,
      clientIp,
    );
    if (result.isFailure) {
      const err = result.getError();
      const status = err.includes('not found') ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
      throw new HttpException(err, status);
    }

    return result.getValue();
  }

  @Get('effective')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'Get effective WAF policy configuration formatted for Gateway data plane' })
  @ApiResponse({ status: 200, description: 'Effective policy configuration JSON' })
  @ApiResponse({ status: 404, description: 'Site or active policy not found' })
  async getEffective(@Param('siteId') siteId: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.getEffectiveUseCase.execute(tenantId, siteId);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }

    return result.getValue();
  }
}
