import {
  Controller,
  Get,
  Query,
  HttpStatus,
  HttpException,
  UseGuards,
  Req,
} from '@nestjs/common';
import { Request } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import {
  GetAnalyticsOverviewUseCase,
  GetAnalyticsTimeseriesUseCase,
  GetTopThreatsUseCase,
} from '../application/analytics.use-cases';
import { QueryAnalyticsDto } from './dtos/analytics-query.dto';
import { JwtAuthGuard } from '../../identity/presentation/guards/jwt-auth.guard';
import { RolesGuard } from '../../identity/presentation/guards/roles.guard';
import { Roles } from '../../identity/presentation/guards/roles.decorator';
import { UserRole } from '../../identity/domain/user-role';

@ApiTags('Analytics & Observability')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('analytics')
export class AnalyticsController {
  constructor(
    private readonly overviewUseCase: GetAnalyticsOverviewUseCase,
    private readonly timeseriesUseCase: GetAnalyticsTimeseriesUseCase,
    private readonly topThreatsUseCase: GetTopThreatsUseCase,
  ) {}

  @Get('overview')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'Get overview KPI metrics (block rate, p50/p95 latency, false positive count)' })
  @ApiResponse({ status: 200, description: 'Overview metrics successfully calculated' })
  @ApiResponse({ status: 404, description: 'Protected site not found' })
  async getOverview(@Query() query: QueryAnalyticsDto, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.overviewUseCase.execute(tenantId, query);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }
    return result.getValue();
  }

  @Get('timeseries')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'Get time-series traffic and threat buckets (24h hourly, 7d/30d daily)' })
  @ApiResponse({ status: 200, description: 'Time-series buckets' })
  @ApiResponse({ status: 404, description: 'Protected site not found' })
  async getTimeseries(@Query() query: QueryAnalyticsDto, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.timeseriesUseCase.execute(tenantId, query);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }
    return result.getValue();
  }

  @Get('top-threats')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'Get top attacked URI paths and top trigger reasons' })
  @ApiResponse({ status: 200, description: 'Top threat breakdown' })
  @ApiResponse({ status: 404, description: 'Protected site not found' })
  async getTopThreats(@Query() query: QueryAnalyticsDto, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.topThreatsUseCase.execute(tenantId, query);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }
    return result.getValue();
  }
}
