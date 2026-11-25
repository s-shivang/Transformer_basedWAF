import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  @Get()
  @ApiOperation({ summary: 'Health check probe' })
  check() {
    return {
      status: 'ok',
      service: 'transformer-waf-saas-api',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  }
}
