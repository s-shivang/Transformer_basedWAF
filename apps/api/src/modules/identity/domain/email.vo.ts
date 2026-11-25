import { ValueObject } from '@shared/domain/value-object.base';
import { Result } from '@shared/application/result';

interface EmailProps {
  value: string;
}

export class Email extends ValueObject<EmailProps> {
  private static readonly EMAIL_REGEX =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

  get value(): string {
    return this.props.value;
  }

  private constructor(props: EmailProps) {
    super(props);
  }

  public static create(email: string): Result<Email> {
    if (!email || typeof email !== 'string') {
      return Result.fail<Email>('Email must be a valid string');
    }

    const normalized = email.trim().toLowerCase();

    if (normalized.length === 0 || normalized.length > 255) {
      return Result.fail<Email>('Email length must be between 1 and 255 characters');
    }

    if (!Email.EMAIL_REGEX.test(normalized)) {
      return Result.fail<Email>('Invalid email address format');
    }

    return Result.ok<Email>(new Email({ value: normalized }));
  }
}
