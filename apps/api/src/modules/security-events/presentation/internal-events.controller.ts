import {
  Controller,
  Post,
  Body,
  HttpStatus,
  HttpException,
  UseGuards,
  HttpCode,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiHeader } from '@nestjs/swagger';
import { InternalIngestKeyGuard } from './guards/internal-ingest-key.guard';
import { IngestSecurityEventsUseCase } from '../application/security-event.use-cases';
import {
  IngestSecurityEventDto,
  BatchIngestEventsDto,
} from './dtos/ingest-event.dto';

@ApiTags('Internal Gateway Ingestion')
@Controller('internal/events')
@UseGuards(InternalIngestKeyGuard)
export class InternalEventsController {
  constructor(private readonly ingestUseCase: IngestSecurityEventsUseCase) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Ingest single security event from Python WAF Gateway' })
  @ApiHeader({ name: 'X-WAF-Ingest-Key', required: true, description: 'Internal Gateway Secret Key' })
  @ApiResponse({ status: 201, description: 'Event ingested successfully' })
  @ApiResponse({ status: 400, description: 'Validation failed' })
  @ApiResponse({ status: 401, description: 'Missing or invalid ingest key' })
  async ingestSingle(@Body() dto: IngestSecurityEventDto) {
    const result = await this.ingestUseCase.execute([dto]);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.BAD_REQUEST);
    }
    return result.getValue();
  }

  @Post('batch')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Ingest batch security events (up to 100) from Python WAF Gateway' })
  @ApiHeader({ name: 'X-WAF-Ingest-Key', required: true, description: 'Internal Gateway Secret Key' })
  @ApiResponse({ status: 201, description: 'Events batch ingested successfully' })
  @ApiResponse({ status: 400, description: 'Validation failed or batch limit exceeded' })
  @ApiResponse({ status: 401, description: 'Missing or invalid ingest key' })
  async ingestBatch(@Body() dto: BatchIngestEventsDto) {
    const result = await this.ingestUseCase.execute(dto.events);
    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.BAD_REQUEST);
    }
    return result.getValue();
  }
}
