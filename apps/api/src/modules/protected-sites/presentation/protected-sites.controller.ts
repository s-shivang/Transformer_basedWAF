import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
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
  CreateProtectedSiteUseCase,
  ListProtectedSitesUseCase,
  GetProtectedSiteUseCase,
  UpdateProtectedSiteUseCase,
  DeleteProtectedSiteUseCase,
} from '../application/protected-site.use-cases';
import {
  StartSiteOnboardingUseCase,
  GetOnboardingInstructionsUseCase,
  VerifySiteDomainUseCase,
  RetrySiteOnboardingUseCase,
  PauseResumeSiteUseCase,
} from '../application/protected-site-onboarding.use-cases';
import {
  CreateProtectedSiteDto,
  UpdateProtectedSiteDto,
  StartSiteOnboardingDto,
  RetryOnboardingDto,
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
    private readonly startOnboardingUseCase: StartSiteOnboardingUseCase,
    private readonly getInstructionsUseCase: GetOnboardingInstructionsUseCase,
    private readonly verifyDomainUseCase: VerifySiteDomainUseCase,
    private readonly retryOnboardingUseCase: RetrySiteOnboardingUseCase,
    private readonly pauseResumeUseCase: PauseResumeSiteUseCase,
  ) {}

  @Post('onboarding')
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Initiate site onboarding state machine with domain verification challenge' })
  @ApiResponse({ status: 201, description: 'Site onboarding created in PENDING_VERIFICATION state' })
  @ApiResponse({ status: 400, description: 'Quota exceeded or validation error' })
  @ApiResponse({ status: 409, description: 'Domain already claimed' })
  async startOnboarding(@Body() dto: StartSiteOnboardingDto, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.startOnboardingUseCase.execute(tenantId, dto, userId, clientIp);
    if (result.isFailure) {
      const err = result.getError();
      const status = err.includes('already claimed')
        ? HttpStatus.CONFLICT
        : err.includes('quota')
          ? HttpStatus.BAD_REQUEST
          : HttpStatus.BAD_REQUEST;
      throw new HttpException(err, status);
    }

    return result.getValue();
  }

  @Get(':siteId/onboarding')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'Get current onboarding status, verification token and DNS instructions' })
  @ApiResponse({ status: 200, description: 'Onboarding instructions' })
  @ApiResponse({ status: 404, description: 'Protected site not found' })
  async getInstructions(@Param('siteId') siteId: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.getInstructionsUseCase.execute(tenantId, siteId);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }

    return result.getValue();
  }

  @Post(':siteId/onboarding/verify-domain')
  @HttpCode(HttpStatus.OK)
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Trigger DNS TXT record check to advance onboarding from PENDING_VERIFICATION to VERIFIED' })
  @ApiResponse({ status: 200, description: 'Domain ownership verified successfully' })
  @ApiResponse({ status: 400, description: 'Verification failed or TXT record mismatch' })
  async verifyDomain(@Param('siteId') siteId: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.verifyDomainUseCase.execute(tenantId, siteId, userId, clientIp);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.BAD_REQUEST);
    }

    return result.getValue();
  }

  @Post(':siteId/onboarding/retry')
  @HttpCode(HttpStatus.OK)
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Retry onboarding from FAILED state' })
  @ApiResponse({ status: 200, description: 'Onboarding reset for retry' })
  @ApiResponse({ status: 400, description: 'Cannot retry from current state' })
  async retryOnboarding(
    @Param('siteId') siteId: string,
    @Body() dto: RetryOnboardingDto,
    @Req() req: Request,
  ) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.retryOnboardingUseCase.execute(tenantId, siteId, dto, userId, clientIp);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.BAD_REQUEST);
    }

    return result.getValue();
  }

  @Post(':siteId/onboarding/pause')
  @HttpCode(HttpStatus.OK)
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Pause an active protected site' })
  @ApiResponse({ status: 200, description: 'Site paused successfully' })
  async pauseSite(@Param('siteId') siteId: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.pauseResumeUseCase.pause(tenantId, siteId, userId, clientIp);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.BAD_REQUEST);
    }

    return result.getValue();
  }

  @Post(':siteId/onboarding/resume')
  @HttpCode(HttpStatus.OK)
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Resume a paused protected site' })
  @ApiResponse({ status: 200, description: 'Site resumed successfully' })
  async resumeSite(@Param('siteId') siteId: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.pauseResumeUseCase.resume(tenantId, siteId, userId, clientIp);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.BAD_REQUEST);
    }

    return result.getValue();
  }

  @Post()
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Register a new protected site and provision default v1 MONITOR policy (Legacy)' })
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
