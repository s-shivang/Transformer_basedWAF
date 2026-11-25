export const DNS_VERIFIER = Symbol('IDnsVerifier');

export interface DnsVerificationResult {
  verified: boolean;
  foundRecords: string[];
  error?: string;
}

export interface TrafficVerificationResult {
  pointed: boolean;
  resolvedTargets: string[];
  error?: string;
}

export interface IDnsVerifier {
  verifyTxtRecord(domain: string, expectedToken: string): Promise<DnsVerificationResult>;
  verifyTrafficRecord(domain: string, expectedTarget: string): Promise<TrafficVerificationResult>;
}
