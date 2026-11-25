export interface JobOptions {
  attempts?: number;
  backoff?: {
    type: 'fixed' | 'exponential';
    delay: number;
  };
  priority?: number;
  delay?: number;
}

export interface Job<T = any> {
  id: string;
  name: string;
  data: T;
  attemptsMade?: number;
}

export type JobHandler<T = any> = (job: Job<T>) => Promise<void>;

export interface JobCounts {
  waiting: number;
  active: number;
  completed: number;
  failed: number;
}

export interface IJobQueue {
  enqueue<T = any>(
    queueName: string,
    jobName: string,
    payload: T,
    opts?: JobOptions,
  ): Promise<string>;

  registerProcessor<T = any>(queueName: string, handler: JobHandler<T>): void;

  getJobCounts(queueName: string): Promise<JobCounts>;

  close(): Promise<void>;
}
