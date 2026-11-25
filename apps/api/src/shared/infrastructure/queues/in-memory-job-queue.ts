import {
  IJobQueue,
  Job,
  JobCounts,
  JobHandler,
  JobOptions,
} from './job-queue.interface';

export class InMemoryJobQueue implements IJobQueue {
  private handlers = new Map<string, JobHandler[]>();
  private jobs = new Map<string, Job[]>();
  private completedJobs = new Map<string, Job[]>();
  private failedJobs = new Map<string, { job: Job; error: any }[]>();
  private pendingPromises: Promise<any>[] = [];

  async enqueue<T = any>(
    queueName: string,
    jobName: string,
    payload: T,
    opts?: JobOptions,
  ): Promise<string> {
    const id = `job_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const job: Job<T> = {
      id,
      name: jobName,
      data: payload,
      attemptsMade: 0,
    };

    if (!this.jobs.has(queueName)) {
      this.jobs.set(queueName, []);
    }
    this.jobs.get(queueName)!.push(job);

    // If processor handlers are registered for this queue, execute them
    const queueHandlers = this.handlers.get(queueName) || [];
    for (const handler of queueHandlers) {
      const execPromise = (async () => {
        try {
          await handler(job);
          if (!this.completedJobs.has(queueName)) {
            this.completedJobs.set(queueName, []);
          }
          this.completedJobs.get(queueName)!.push(job);
        } catch (error) {
          const maxAttempts = opts?.attempts || 1;
          job.attemptsMade = (job.attemptsMade || 0) + 1;
          if (job.attemptsMade < maxAttempts) {
            // retry
            try {
              await handler(job);
              if (!this.completedJobs.has(queueName)) {
                this.completedJobs.set(queueName, []);
              }
              this.completedJobs.get(queueName)!.push(job);
              return;
            } catch (retryErr) {
              // fall-through to fail
            }
          }
          if (!this.failedJobs.has(queueName)) {
            this.failedJobs.set(queueName, []);
          }
          this.failedJobs.get(queueName)!.push({ job, error });
        }
      })();
      this.pendingPromises.push(execPromise);
    }

    return id;
  }

  registerProcessor<T = any>(queueName: string, handler: JobHandler<T>): void {
    if (!this.handlers.has(queueName)) {
      this.handlers.set(queueName, []);
    }
    this.handlers.get(queueName)!.push(handler);
  }

  async getJobCounts(queueName: string): Promise<JobCounts> {
    const total = (this.jobs.get(queueName) || []).length;
    const completed = (this.completedJobs.get(queueName) || []).length;
    const failed = (this.failedJobs.get(queueName) || []).length;
    const active = Math.max(0, total - completed - failed);

    return {
      waiting: 0,
      active,
      completed,
      failed,
    };
  }

  async drain(): Promise<void> {
    await Promise.allSettled(this.pendingPromises);
    this.pendingPromises = [];
  }

  getCompletedJobs(queueName?: string): Job[] {
    if (queueName) {
      return this.completedJobs.get(queueName) || [];
    }
    const all: Job[] = [];
    this.completedJobs.forEach((jobs) => all.push(...jobs));
    return all;
  }

  getFailedJobs(queueName?: string): { job: Job; error: any }[] {
    if (queueName) {
      return this.failedJobs.get(queueName) || [];
    }
    const all: { job: Job; error: any }[] = [];
    this.failedJobs.forEach((fails) => all.push(...fails));
    return all;
  }

  clear(): void {
    this.jobs.clear();
    this.completedJobs.clear();
    this.failedJobs.clear();
    this.pendingPromises = [];
  }

  async close(): Promise<void> {
    await this.drain();
  }
}
