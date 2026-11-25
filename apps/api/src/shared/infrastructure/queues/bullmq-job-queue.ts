import { Queue, Worker, JobsOptions } from 'bullmq';
import Redis from 'ioredis';
import {
  IJobQueue,
  JobCounts,
  JobHandler,
  JobOptions,
} from './job-queue.interface';

export class BullMqJobQueue implements IJobQueue {
  private redisConnection: Redis;
  private queues = new Map<string, Queue>();
  private workers = new Map<string, Worker[]>();

  constructor(redisUrl?: string) {
    this.redisConnection = new Redis(redisUrl || 'redis://localhost:6379', {
      maxRetriesPerRequest: null,
      enableReadyCheck: false,
    });
  }

  private getQueue(queueName: string): Queue {
    if (!this.queues.has(queueName)) {
      const queue = new Queue(queueName, {
        connection: this.redisConnection,
        defaultJobOptions: {
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 1000,
          },
          removeOnComplete: true,
          removeOnFail: false,
        },
      });
      this.queues.set(queueName, queue);
    }
    return this.queues.get(queueName)!;
  }

  async enqueue<T = any>(
    queueName: string,
    jobName: string,
    payload: T,
    opts?: JobOptions,
  ): Promise<string> {
    const queue = this.getQueue(queueName);
    const bullOpts: JobsOptions = {};

    if (opts?.attempts !== undefined) {
      bullOpts.attempts = opts.attempts;
    }
    if (opts?.backoff) {
      bullOpts.backoff = opts.backoff;
    }
    if (opts?.delay !== undefined) {
      bullOpts.delay = opts.delay;
    }
    if (opts?.priority !== undefined) {
      bullOpts.priority = opts.priority;
    }

    const job = await queue.add(jobName, payload, bullOpts);
    return job.id || `${queueName}_${Date.now()}`;
  }

  registerProcessor<T = any>(queueName: string, handler: JobHandler<T>): void {
    const worker = new Worker(
      queueName,
      async (bullJob) => {
        await handler({
          id: bullJob.id || '',
          name: bullJob.name,
          data: bullJob.data,
          attemptsMade: bullJob.attemptsMade,
        });
      },
      {
        connection: this.redisConnection,
      },
    );

    worker.on('failed', (job, err) => {
      if (job && job.attemptsMade >= (job.opts?.attempts || 3)) {
        console.error(
          `[DEAD-LETTER] Queue ${queueName} Job ${job.id} (${job.name}) permanently failed after ${job.attemptsMade} attempts: ${err.message}`,
        );
      }
    });

    if (!this.workers.has(queueName)) {
      this.workers.set(queueName, []);
    }
    this.workers.get(queueName)!.push(worker);
  }

  async getJobCounts(queueName: string): Promise<JobCounts> {
    const queue = this.getQueue(queueName);
    const counts = await queue.getJobCounts('waiting', 'active', 'completed', 'failed');
    return {
      waiting: counts.waiting || 0,
      active: counts.active || 0,
      completed: counts.completed || 0,
      failed: counts.failed || 0,
    };
  }

  async close(): Promise<void> {
    for (const workers of this.workers.values()) {
      for (const worker of workers) {
        await worker.close();
      }
    }
    for (const queue of this.queues.values()) {
      await queue.close();
    }
    await this.redisConnection.quit();
  }
}
