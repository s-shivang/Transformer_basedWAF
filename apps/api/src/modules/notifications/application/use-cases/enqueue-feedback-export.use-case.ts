import { Inject, Injectable } from '@nestjs/common';
import { IJobQueue } from '@shared/infrastructure/queues/job-queue.interface';
import { JOB_QUEUE_TOKEN, QUEUES, JOBS } from '@shared/infrastructure/queues/queue.constants';

@Injectable()
export class EnqueueFeedbackExportUseCase {
  constructor(
    @Inject(JOB_QUEUE_TOKEN) private readonly jobQueue: IJobQueue,
  ) {}

  async execute(
    tenantId: string,
    userId: string,
  ): Promise<{ jobId: string; status: string; message: string }> {
    const jobId = await this.jobQueue.enqueue(
      QUEUES.FEEDBACK_EXPORT,
      JOBS.EXPORT_FEEDBACK,
      {
        tenantId,
        userId,
      },
    );

    return {
      jobId,
      status: 'QUEUED',
      message: 'Feedback export job accepted. You will receive an in-app notification when ready.',
    };
  }
}
