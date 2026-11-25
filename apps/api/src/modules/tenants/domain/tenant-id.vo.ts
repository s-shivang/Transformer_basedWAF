import { ValueObject } from '@shared/domain/value-object.base';
import { Result } from '@shared/application/result';

interface TenantIdProps {
  value: string;
}

export class TenantId extends ValueObject<TenantIdProps> {
  get value(): string {
    return this.props.value;
  }

  private constructor(props: TenantIdProps) {
    super(props);
  }

  public static create(id: string): Result<TenantId> {
    if (!id || id.trim().length === 0) {
      return Result.fail<TenantId>('TenantId cannot be empty');
    }
    return Result.ok<TenantId>(new TenantId({ value: id.trim() }));
  }
}
