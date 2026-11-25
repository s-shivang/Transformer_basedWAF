import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Request } from 'express';

@Injectable()
export class TenantScopeGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const tenantContext = request.tenantContext;

    if (!tenantContext || !tenantContext.tenantId) {
      throw new ForbiddenException('Tenant context not established');
    }

    // Check if route params contain tenantId or id
    const routeParams = request.params;
    const requestedTenantId = routeParams?.['tenantId'] || routeParams?.['id'];

    if (requestedTenantId && requestedTenantId !== tenantContext.tenantId) {
      // Cross-tenant access attempted: return generic 403 Forbidden without leaking existence
      throw new ForbiddenException('Access to requested tenant is forbidden');
    }

    return true;
  }
}
