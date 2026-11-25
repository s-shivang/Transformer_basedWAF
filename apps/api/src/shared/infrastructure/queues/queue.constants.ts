export const JOB_QUEUE_TOKEN = 'JOB_QUEUE';

export const QUEUES = {
  ALERTS: 'alerts',
  POLICY_SYNC: 'policy-sync',
  FEEDBACK_EXPORT: 'feedback-export',
} as const;

export const JOBS = {
  PROCESS_ALERTS: 'process-alerts',
  SYNC_POLICY: 'sync-policy',
  EXPORT_FEEDBACK: 'export-feedback',
} as const;
