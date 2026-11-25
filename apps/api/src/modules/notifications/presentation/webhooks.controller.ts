import {
  Controller,
  Get,
  Post,
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
import { JwtAuthGuard } from '../../identity/presentation/guards/jwt-auth.guard';
import { RolesGuard } from '../../identity/presentation/guards/roles.guard';
import { Roles } from '../../identity/presentation/guards/roles.decorator';
import { UserRole } from '../../identity/domain/user-role';
import { CreateWebhookUseCase } from '../application/use-cases/create-webhook.use-case';
import {
  ListWebhooksUseCase,
  DeleteWebhookUseCase,
} from '../application/use-cases/webhook-queries.use-case';
import { CreateWebhookDto } from './dtos/create-webhook.dto';

@ApiTags('Webhooks & Alert Endpoints')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('webhooks')
export class WebhooksController {
  constructor(
    private readonly createWebhookUseCase: CreateWebhookUseCase,
    private readonly listWebhooksUseCase: ListWebhooksUseCase,
    private readonly deleteWebhookUseCase: DeleteWebhookUseCase,
  ) {}

  @Post()
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Register a new webhook endpoint for tenant alert notifications' })
  @ApiResponse({ status: 201, description: 'Webhook registered (signing secret returned once)' })
  async createWebhook(@Body() dto: CreateWebhookDto, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    try {
      return await this.createWebhookUseCase.execute(tenantId, dto);
    } catch (err: any) {
      throw new HttpException(err.message || 'Failed to create webhook', HttpStatus.BAD_REQUEST);
    }
  }

  @Get()
  @Roles(UserRole.VIEWER)
  @ApiOperation({ summary: 'List all active webhook endpoints for tenant (never returns secret)' })
  @ApiResponse({ status: 200, description: 'List of webhook endpoints' })
  async listWebhooks(@Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    return this.listWebhooksUseCase.execute(tenantId);
  }

  @Delete(':id')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Delete a registered webhook endpoint' })
  @ApiResponse({ status: 200, description: 'Webhook deleted' })
  async deleteWebhook(@Param('id') id: string, @Req() req: Request) {
    const tenantId = req.tenantContext?.tenantId;
    if (!tenantId) {
      throw new HttpException('Tenant context required', HttpStatus.FORBIDDEN);
    }

    await this.deleteWebhookUseCase.execute(id, tenantId);
    return { success: true, message: `Webhook ${id} deleted` };
  }
}
