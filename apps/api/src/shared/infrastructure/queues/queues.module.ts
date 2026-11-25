import { Global, Module } from '@nestjs/common';
import { JOB_QUEUE_TOKEN } from './queue.constants';
import { InMemoryJobQueue } from './in-memory-job-queue';
import { BullMqJobQueue } from './bullmq-job-queue';

@Global()
@Module({
  providers: [
    {
      provide: JOB_QUEUE_TOKEN,
      useFactory: () => {
        const redisUrl = process.env.REDIS_URL;
        const isTest = process.env.NODE_ENV === 'test';
        if (redisUrl && !isTest) {
          return new BullMqJobQueue(redisUrl);
        }
        return new InMemoryJobQueue();
      },
    },
  ],
  exports: [JOB_QUEUE_TOKEN],
})
export class QueuesModule {}
