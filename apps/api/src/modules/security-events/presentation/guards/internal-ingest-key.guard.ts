import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';

@Injectable()
export class InternalIngestKeyGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const providedKey = request.headers['x-waf-ingest-key'];
    const expectedKey = process.env.WAF_INGEST_KEY || 'waf-internal-ingest-secret-dev';

    if (!providedKey || providedKey !== expectedKey) {
      throw new UnauthorizedException('Missing or invalid X-WAF-Ingest-Key header');
    }

    return true;
  }
}
