import { Injectable } from '@nestjs/common';
import {
  IDnsVerifier,
  DnsVerificationResult,
  TrafficVerificationResult,
} from '../../domain/dns-verifier.interface';

@Injectable()
export class LocalDevDnsVerifier implements IDnsVerifier {
  private txtRecords: Map<string, Set<string>> = new Map();
  private trafficRecords: Map<string, Set<string>> = new Map();
  private defaultSuccess = false;

  public setDefaultSuccess(success: boolean) {
    this.defaultSuccess = success;
  }

  public registerTxtRecord(domain: string, token: string) {
    const key = domain.trim().toLowerCase();
    if (!this.txtRecords.has(key)) {
      this.txtRecords.set(key, new Set());
    }
    this.txtRecords.get(key)!.add(token.trim());
  }

  public registerTrafficRecord(domain: string, target: string) {
    const key = domain.trim().toLowerCase();
    if (!this.trafficRecords.has(key)) {
      this.trafficRecords.set(key, new Set());
    }
    this.trafficRecords.get(key)!.add(target.trim().toLowerCase());
  }

  public clear() {
    this.txtRecords.clear();
    this.trafficRecords.clear();
    this.defaultSuccess = false;
  }

  async verifyTxtRecord(domain: string, expectedToken: string): Promise<DnsVerificationResult> {
    const cleanDomain = domain.trim().toLowerCase();
    const records = this.txtRecords.get(cleanDomain) || this.txtRecords.get(`_waf-challenge.${cleanDomain}`);

    if (records && records.has(expectedToken.trim())) {
      return {
        verified: true,
        foundRecords: Array.from(records),
      };
    }

    if (this.defaultSuccess || cleanDomain === 'localhost' || cleanDomain.endsWith('.test')) {
      return {
        verified: true,
        foundRecords: [expectedToken.trim()],
      };
    }

    const foundRecords = records ? Array.from(records) : [];
    return {
      verified: false,
      foundRecords,
      error: `LocalDev: No matching TXT record found for ${expectedToken} on ${cleanDomain}`,
    };
  }

  async verifyTrafficRecord(domain: string, expectedTarget: string): Promise<TrafficVerificationResult> {
    const cleanDomain = domain.trim().toLowerCase();
    const records = this.trafficRecords.get(cleanDomain);

    if (records && records.has(expectedTarget.trim().toLowerCase())) {
      return {
        pointed: true,
        resolvedTargets: Array.from(records),
      };
    }

    if (this.defaultSuccess || cleanDomain === 'localhost' || cleanDomain.endsWith('.test')) {
      return {
        pointed: true,
        resolvedTargets: [expectedTarget.trim()],
      };
    }

    const resolved = records ? Array.from(records) : [];
    return {
      pointed: false,
      resolvedTargets: resolved,
      error: `LocalDev: Domain ${cleanDomain} does not point to ${expectedTarget}`,
    };
  }
}
