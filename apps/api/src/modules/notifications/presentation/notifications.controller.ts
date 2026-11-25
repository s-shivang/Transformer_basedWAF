import {
  Controller,
  Get,
  Patch,
  Post,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  HttpException,
  UseGuards,
  Req,
} from '@nestjs/common';
import { Request } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../identity/presentation/guards/jwt-auth.guard';
import { RolesGuard } from '../../identity/presentation/guards/roles.guard';
import { Roles } from '../../identity/presentation/guards/roles.decorator';
import { UserRole } from '../../identity/domain/user-role';
import { GetNotificationsUseCase } from '../application/use-cases/get-notifications.use-case';
import { MarkNotificationReadUseCase } from '../application/use-cases/mark-notification-read.use-case';
import { EnqueueFeedbackExportUseCase } from '../application/use-cases/enqueue-feedback-export.use-case';
import { QueryNotificationsDto } from './dtos/query-notifications.dto';

@ApiTags('Notifications & Alerts')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller()
export class NotificationsController {
  constructor(
    private readonly getNotificationsUseCase: GetNotificationsUseCase,
    private readonly markNotificationReadUseCase: MarkNotificationReadUseCase,
    private readonly enqueueFeedbackExportUseCase: EnqueueFeedbackExportUseCase,
  ) {}

  @Get('notifications')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'List notifications strictly scoped to active tenant' })
  @ApiResponse({ status: 200, description: 'Paginated notifications list' })
  async getNotifications(
    @Query() query: QueryNotificationsDto,
    @Req() req: Request,
  ) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const result = await this.getNotificationsUseCase.execute(tenantId, {
      isRead: query.isRead,
      limit: query.limit,
      offset: query.offset,
    });

    return {
      items: result.notifications.map((n) => ({
        id: n.id,
        tenantId: n.tenantId,
        siteId: n.siteId,
        severity: n.severity,
        type: n.type,
        title: n.title,
        message: n.message,
        metadata: n.metadataJson,
        isRead: n.isRead,
        readAt: n.readAt,
        createdAt: n.createdAt,
      })),
      total: result.total,
    };
  }

  @Patch('notifications/:id/read')
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'Mark an in-app notification as read' })
  @ApiResponse({ status: 200, description: 'Notification updated' })
  async markAsRead(@Param('id') id: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    const n = await this.markNotificationReadUseCase.execute(id, tenantId);
    return {
      id: n.id,
      tenantId: n.tenantId,
      siteId: n.siteId,
      severity: n.severity,
      type: n.type,
      title: n.title,
      message: n.message,
      metadata: n.metadataJson,
      isRead: n.isRead,
      readAt: n.readAt,
      createdAt: n.createdAt,
    };
  }

  @Post('feedback/export')
  @Roles(UserRole.ADMIN)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Enqueue an offline ML dataset export job for approved feedback' })
  @ApiResponse({ status: 202, description: 'Job enqueued successfully' })
  async enqueueFeedbackExport(@Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    const userId = req.tenantContext?.userId;
    if (!tenantId || !userId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    return this.enqueueFeedbackExportUseCase.execute(tenantId, userId);
  }
}
