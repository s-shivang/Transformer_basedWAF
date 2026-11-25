import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { ITokenService, TOKEN_SERVICE } from '../../infrastructure/token.service';

export interface AuthenticatedUserContext {
  userId: string;
  tenantId: string;
  role: string;
  email: string;
}

declare global {
  namespace Express {
    interface Request {
      tenantContext?: AuthenticatedUserContext;
    }
  }
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(@Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();

    // 1. Prefer Authorization: Bearer <token> header if present (for API clients / tests)
    let token: string | undefined;
    if (request.headers.authorization) {
      const parts = request.headers.authorization.split(' ');
      if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
        token = parts[1];
      }
    }

    // 2. Fallback to HttpOnly cookie 'waf_access_token' (for web clients)
    if (!token) {
      token = request.cookies?.['waf_access_token'];
    }

    if (!token) {
      throw new UnauthorizedException('Authentication credentials missing');
    }

    const payload = this.tokenService.verifyAccessToken(token);
    if (!payload) {
      throw new UnauthorizedException('Invalid or expired access token');
    }

    request.tenantContext = {
      userId: payload.sub,
      tenantId: payload.tenantId,
      role: payload.role,
      email: payload.email,
    };

    return true;
  }
}
