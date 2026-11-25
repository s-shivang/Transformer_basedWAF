import { Entity } from '@shared/domain/entity.base';
import { Result } from '@shared/application/result';

export interface AuditLogProps {
  tenantId: string;
  userId?: string | null;
  action: string;
  resource: string;
  resourceId?: string | null;
  metadata?: any;
  ipAddress?: string | null;
  createdAt: Date;
}

export class AuditLog extends Entity<string> {
  private _props: AuditLogProps;

  private constructor(id: string, props: AuditLogProps) {
    super(id);
    this._props = props;
  }

  get tenantId(): string {
    return this._props.tenantId;
  }

  get userId(): string | null {
    return this._props.userId ?? null;
  }

  get action(): string {
    return this._props.action;
  }

  get resource(): string {
    return this._props.resource;
  }

  get resourceId(): string | null {
    return this._props.resourceId ?? null;
  }

  get metadata(): any {
    return this._props.metadata;
  }

  get ipAddress(): string | null {
    return this._props.ipAddress ?? null;
  }

  get createdAt(): Date {
    return this._props.createdAt;
  }

  public static create(
    props: {
      tenantId: string;
      userId?: string | null;
      action: string;
      resource: string;
      resourceId?: string | null;
      metadata?: any;
      ipAddress?: string | null;
    },
    id?: string,
  ): Result<AuditLog> {
    if (!props.tenantId) return Result.fail<AuditLog>('tenantId is required');
    if (!props.action) return Result.fail<AuditLog>('action is required');
    if (!props.resource) return Result.fail<AuditLog>('resource is required');

    const logId = id ?? crypto.randomUUID();
    const log = new AuditLog(logId, {
      tenantId: props.tenantId,
      userId: props.userId ?? null,
      action: props.action,
      resource: props.resource,
      resourceId: props.resourceId ?? null,
      metadata: props.metadata,
      ipAddress: props.ipAddress ?? null,
      createdAt: new Date(),
    });

    return Result.ok<AuditLog>(log);
  }

  public static reconstitute(id: string, props: AuditLogProps): AuditLog {
    return new AuditLog(id, props);
  }
}
