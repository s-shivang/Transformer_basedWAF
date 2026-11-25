import { ValueObject } from '@shared/domain/value-object.base';
import { Result } from '@shared/application/result';

export interface ScopedExclusionProps {
  id: string;
  pathPrefix: string;
  parameterName?: string | null;
  reason: string;
  skipMl: boolean;
  skipRules: boolean;
  createdAt: Date;
}

export class ScopedExclusion extends ValueObject<ScopedExclusionProps> {
  get id(): string {
    return this.props.id;
  }

  get pathPrefix(): string {
    return this.props.pathPrefix;
  }

  get parameterName(): string | null {
    return this.props.parameterName ?? null;
  }

  get reason(): string {
    return this.props.reason;
  }

  get skipMl(): boolean {
    return this.props.skipMl;
  }

  get skipRules(): boolean {
    return this.props.skipRules;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  private constructor(props: ScopedExclusionProps) {
    super(props);
  }

  public static create(props: {
    id?: string;
    pathPrefix: string;
    parameterName?: string | null;
    reason: string;
    skipMl?: boolean;
    skipRules?: boolean;
    createdAt?: Date;
  }): Result<ScopedExclusion> {
    if (!props.pathPrefix || typeof props.pathPrefix !== 'string') {
      return Result.fail<ScopedExclusion>('pathPrefix must be a valid path string');
    }

    const path = props.pathPrefix.trim();
    if (!path.startsWith('/')) {
      return Result.fail<ScopedExclusion>('pathPrefix must start with a leading slash ("/")');
    }

    // Invariant: Reject overly broad full-site bypass wildcards "*" or bare "/" unless specific
    if (path === '*' || path === '/*') {
      return Result.fail<ScopedExclusion>('Overly broad wildcard exclusions are forbidden');
    }

    if (!props.reason || props.reason.trim().length < 5) {
      return Result.fail<ScopedExclusion>('A detailed justification reason (>= 5 chars) is required for exclusions');
    }

    return Result.ok<ScopedExclusion>(
      new ScopedExclusion({
        id: props.id ?? crypto.randomUUID(),
        pathPrefix: path,
        parameterName: props.parameterName?.trim() || null,
        reason: props.reason.trim(),
        skipMl: props.skipMl ?? true,
        skipRules: props.skipRules ?? false,
        createdAt: props.createdAt ?? new Date(),
      }),
    );
  }
}
