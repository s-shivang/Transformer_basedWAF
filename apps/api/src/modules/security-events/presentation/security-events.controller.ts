import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  Query,
  HttpStatus,
  HttpException,
  UseGuards,
  Req,
} from '@nestjs/common';
import { Request } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import {
  QuerySecurityEventsUseCase,
  GetSecurityEventByIdUseCase,
  SubmitEventFeedbackUseCase,
  ListFeedbackQueueUseCase,
  ReviewEventFeedbackUseCase,
} from '../application/security-event.use-cases';
import { QuerySecurityEventsDto } from './dtos/security-event-query.dto';
import {
  SubmitFeedbackDto,
  ReviewFeedbackDto,
  QueryFeedbackDto,
} from './dtos/feedback.dto';
import { JwtAuthGuard } from '../../identity/presentation/guards/jwt-auth.guard';
import { RolesGuard } from '../../identity/presentation/guards/roles.guard';
import { Roles } from '../../identity/presentation/guards/roles.decorator';
import { UserRole } from '../../identity/domain/user-role';

@ApiTags('Security Events & Feedback Queue')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller()
export class SecurityEventsController {
  constructor(
    private readonly queryEventsUseCase: QuerySecurityEventsUseCase,
    private readonly getEventByIdUseCase: GetSecurityEventByIdUseCase,
    private readonly submitFeedbackUseCase: SubmitEventFeedbackUseCase,
    private readonly listFeedbackUseCase: ListFeedbackQueueUseCase,
    private readonly reviewFeedbackUseCase: ReviewEventFeedbackUseCase,
  ) {}

  @Get('events')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'Query paginated security events strictly scoped to active tenant' })
  @ApiResponse({ status: 200, description: 'Paginated security events' })
  async queryEvents(@Query() query: QuerySecurityEventsDto, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.queryEventsUseCase.execute(tenantId, query);
    return result.getValue();
  }

  @Get('events/:eventId')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'Get security event by ID (returns 404 if not found or cross-tenant)' })
  @ApiResponse({ status: 200, description: 'Security event details' })
  @ApiResponse({ status: 404, description: 'Event not found' })
  async getEvent(@Param('eventId') eventId: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.getEventByIdUseCase.execute(tenantId, eventId);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.NOT_FOUND);
    }
    return result.getValue();
  }

  @Post('events/:eventId/feedback')
  @Roles(UserRole.OWNER, UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Submit feedback (e.g. False Positive) into human review queue' })
  @ApiResponse({ status: 201, description: 'Feedback submitted into PENDING_REVIEW queue' })
  @ApiResponse({ status: 400, description: 'Validation failed' })
  @ApiResponse({ status: 403, description: 'Forbidden (VIEWER cannot submit feedback)' })
  @ApiResponse({ status: 404, description: 'Security event not found' })
  async submitFeedback(
    @Param('eventId') eventId: string,
    @Body() dto: SubmitFeedbackDto,
    @Req() req: Request,
  ) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = req.tenantContext?.userId || (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.submitFeedbackUseCase.execute(
      tenantId,
      eventId,
      dto,
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

  @Get('feedback')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'List false-positive and attack feedback queue items for active tenant' })
  @ApiResponse({ status: 200, description: 'Paginated feedback items' })
  async listFeedback(@Query() query: QueryFeedbackDto, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.listFeedbackUseCase.execute(tenantId, query);
    return result.getValue();
  }

  @Patch('feedback/:feedbackId/review')
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Review feedback queue item: transition to APPROVED or REJECTED' })
  @ApiResponse({ status: 200, description: 'Feedback reviewed successfully' })
  @ApiResponse({ status: 400, description: 'Invalid transition (already finalized)' })
  @ApiResponse({ status: 403, description: 'Forbidden (ANALYST and VIEWER cannot review)' })
  @ApiResponse({ status: 404, description: 'Feedback item not found' })
  async reviewFeedback(
    @Param('feedbackId') feedbackId: string,
    @Body() dto: ReviewFeedbackDto,
    @Req() req: Request,
  ) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const userId = req.tenantContext?.userId || (req as any).user?.sub;
    const clientIp = req.ip;

    const result = await this.reviewFeedbackUseCase.execute(
      tenantId,
      feedbackId,
      dto,
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
}
