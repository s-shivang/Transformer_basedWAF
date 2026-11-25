import { ValueObject } from '@shared/domain/value-object.base';
import { Result } from '@shared/application/result';

export interface PolicyThresholdsProps {
  monitorThreshold: number;
  challengeThreshold: number;
  blockThreshold: number;
}

export class PolicyThresholds extends ValueObject<PolicyThresholdsProps> {
  get monitorThreshold(): number {
    return this.props.monitorThreshold;
  }

  get challengeThreshold(): number {
    return this.props.challengeThreshold;
  }

  get blockThreshold(): number {
    return this.props.blockThreshold;
  }

  private constructor(props: PolicyThresholdsProps) {
    super(props);
  }

  public static create(
    monitor: number = 0.05,
    challenge: number = 0.50,
    block: number = 0.85,
  ): Result<PolicyThresholds> {
    if (typeof monitor !== 'number' || typeof challenge !== 'number' || typeof block !== 'number') {
      return Result.fail<PolicyThresholds>('Thresholds must be numeric values');
    }

    // Invariant: 0.0 < monitor < challenge < block <= 1.0
    if (monitor <= 0.0 || monitor >= 1.0) {
      return Result.fail<PolicyThresholds>('monitorThreshold must be between 0.0 and 1.0');
    }

    if (challenge <= monitor) {
      return Result.fail<PolicyThresholds>('challengeThreshold must be strictly greater than monitorThreshold');
    }

    if (block <= challenge || block > 1.0) {
      return Result.fail<PolicyThresholds>('blockThreshold must be strictly greater than challengeThreshold and <= 1.0');
    }

    return Result.ok<PolicyThresholds>(
      new PolicyThresholds({
        monitorThreshold: Math.round(monitor * 10000) / 10000,
        challengeThreshold: Math.round(challenge * 10000) / 10000,
        blockThreshold: Math.round(block * 10000) / 10000,
      }),
    );
  }
}
