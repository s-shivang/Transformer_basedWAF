import { Controller, Get, Inject } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { PrismaService } from './prisma.service';
import { JOB_QUEUE_TOKEN } from './queues/queue.constants';
import { IJobQueue } from './queues/job-queue.interface';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(JOB_QUEUE_TOKEN) private readonly queue: IJobQueue,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Health check probe' })
  async check() {
    let dbStatus = 'disconnected';
    if (process.env.DATABASE_URL) {
      try {
        await this.prisma.$queryRaw`SELECT 1`;
        dbStatus = 'connected';
      } catch {
        dbStatus = 'unreachable';
      }
    } else {
      dbStatus = 'in-memory-mode';
    }

    const queueType = process.env.REDIS_URL && process.env.NODE_ENV !== 'test' ? 'bullmq' : 'in-memory';

    return {
      status: 'ok',
      service: 'transformer-waf-saas-api',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      dependencies: {
        database: dbStatus,
        queue: queueType,
      },
    };
  }
}
