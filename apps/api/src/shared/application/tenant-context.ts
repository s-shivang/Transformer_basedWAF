/**
 * TenantContext holding execution tenant scope.
 */
export interface ITenantContext {
  tenantId: string;
  userId?: string;
  role?: string;
}

export class TenantContext {
  private static currentContext: ITenantContext | null = null;

  public static set(ctx: ITenantContext): void {
    this.currentContext = ctx;
  }

  public static get(): ITenantContext | null {
    return this.currentContext;
  }

  public static clear(): void {
    this.currentContext = null;
  }
}
