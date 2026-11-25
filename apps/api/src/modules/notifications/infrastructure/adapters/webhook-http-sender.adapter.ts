import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';
import {
  IWebhookHttpSender,
  WebhookSendResult,
} from '../../application/ports/webhook-http-sender.port';

@Injectable()
export class FetchWebhookHttpSender implements IWebhookHttpSender {
  async send(
    url: string,
    payload: Record<string, any>,
    signature: string,
  ): Promise<WebhookSendResult> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Transformer-WAF-Alerts/1.0',
          'X-WAF-Signature': signature,
          'X-WAF-Delivery': crypto.randomUUID(),
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      return {
        success: response.ok,
        statusCode: response.status,
        error: response.ok ? undefined : `HTTP ${response.status}`,
      };
    } catch (err: any) {
      return {
        success: false,
        error: err.message || 'Network error',
      };
    }
  }
}

export class InMemoryWebhookHttpSender implements IWebhookHttpSender {
  public dispatched: { url: string; payload: any; signature: string }[] = [];
  public shouldFail = false;

  async send(
    url: string,
    payload: Record<string, any>,
    signature: string,
  ): Promise<WebhookSendResult> {
    this.dispatched.push({ url, payload, signature });
    if (this.shouldFail) {
      return { success: false, statusCode: 500, error: 'Simulated webhook failure' };
    }
    return { success: true, statusCode: 200 };
  }

  clear() {
    this.dispatched = [];
    this.shouldFail = false;
  }
}
