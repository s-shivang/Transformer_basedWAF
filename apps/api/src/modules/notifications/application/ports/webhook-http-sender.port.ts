export interface WebhookSendResult {
  success: boolean;
  statusCode?: number;
  error?: string;
}

export interface IWebhookHttpSender {
  send(
    url: string,
    payload: Record<string, any>,
    signature: string,
  ): Promise<WebhookSendResult>;
}

export const WEBHOOK_HTTP_SENDER = 'WEBHOOK_HTTP_SENDER';
