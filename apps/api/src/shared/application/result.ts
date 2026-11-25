/**
 * Generic Result class for functional error handling without exceptions.
 */
export class Result<T> {
  public isSuccess: boolean;
  public isFailure: boolean;
  private readonly _error: string | null;
  private readonly _value: T | null;

  private constructor(isSuccess: boolean, error?: string | null, value?: T | null) {
    if (isSuccess && error) {
      throw new Error('InvalidOperation: A result cannot be successful and contain an error');
    }
    if (!isSuccess && !error) {
      throw new Error('InvalidOperation: A failing result needs to contain an error message');
    }

    this.isSuccess = isSuccess;
    this.isFailure = !isSuccess;
    this._error = error ?? null;
    this._value = value ?? null;
  }

  public getValue(): T {
    if (!this.isSuccess) {
      throw new Error(`Can't retrieve the value from a failed result: ${this._error}`);
    }
    return this._value as T;
  }

  public getError(): string {
    return this._error ?? '';
  }

  public static ok<U>(value?: U): Result<U> {
    return new Result<U>(true, null, value);
  }

  public static fail<U>(error: string): Result<U> {
    return new Result<U>(false, error, null);
  }
}
