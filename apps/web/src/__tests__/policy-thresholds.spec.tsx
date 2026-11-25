import { describe, it, expect } from 'vitest';

export function validateThresholdOrdering(
  monitorThreshold: number,
  challengeThreshold: number,
  blockThreshold: number,
): { valid: boolean; error?: string } {
  if (monitorThreshold <= 0) {
    return { valid: false, error: 'Monitor threshold must be greater than 0.00' };
  }
  if (monitorThreshold >= challengeThreshold) {
    return { valid: false, error: 'Monitor threshold must be strictly less than Challenge threshold' };
  }
  if (challengeThreshold >= blockThreshold) {
    return { valid: false, error: 'Challenge threshold must be strictly less than Block threshold' };
  }
  if (blockThreshold > 1.0) {
    return { valid: false, error: 'Block threshold cannot exceed 1.00' };
  }
  return { valid: true };
}

describe('Policy 4-Band Threshold Ordering Invariants', () => {
  it('accepts valid default production thresholds (0.05 < 0.50 < 0.85)', () => {
    const result = validateThresholdOrdering(0.05, 0.50, 0.85);
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('accepts custom strict thresholds (0.10 < 0.40 < 0.70)', () => {
    const result = validateThresholdOrdering(0.10, 0.40, 0.70);
    expect(result.valid).toBe(true);
  });

  it('rejects monitor threshold <= 0', () => {
    const result = validateThresholdOrdering(0, 0.50, 0.85);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('greater than 0.00');
  });

  it('rejects inverted monitor and challenge thresholds (0.60 >= 0.50)', () => {
    const result = validateThresholdOrdering(0.60, 0.50, 0.85);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('strictly less than Challenge threshold');
  });

  it('rejects inverted challenge and block thresholds (0.50 >= 0.45)', () => {
    const result = validateThresholdOrdering(0.10, 0.50, 0.45);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('strictly less than Block threshold');
  });

  it('rejects equal challenge and block thresholds (0.80 === 0.80)', () => {
    const result = validateThresholdOrdering(0.20, 0.80, 0.80);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('strictly less than Block threshold');
  });

  it('rejects block threshold exceeding 1.00 (1.05)', () => {
    const result = validateThresholdOrdering(0.10, 0.50, 1.05);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('cannot exceed 1.00');
  });
});
