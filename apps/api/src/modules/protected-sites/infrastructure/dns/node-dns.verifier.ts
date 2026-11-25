import { Injectable } from '@nestjs/common';
import * as dns from 'dns/promises';
import {
  IDnsVerifier,
  DnsVerificationResult,
  TrafficVerificationResult,
} from '../../domain/dns-verifier.interface';

@Injectable()
export class NodeDnsVerifier implements IDnsVerifier {
  async verifyTxtRecord(domain: string, expectedToken: string): Promise<DnsVerificationResult> {
    const cleanDomain = domain.trim().toLowerCase();
    const candidateDomains = [
      `_waf-challenge.${cleanDomain}`,
      cleanDomain,
    ];

    const foundRecords: string[] = [];
    let lastError: string | undefined;

    for (const host of candidateDomains) {
      try {
        const records = await dns.resolveTxt(host);
        for (const chunkGroup of records) {
          const fullRecord = chunkGroup.join('');
          foundRecords.push(fullRecord);
          if (fullRecord.trim() === expectedToken.trim() || fullRecord.includes(expectedToken.trim())) {
            return {
              verified: true,
              foundRecords,
            };
          }
        }
      } catch (err: any) {
        lastError = err.message || String(err);
      }
    }

    return {
      verified: false,
      foundRecords,
      error: foundRecords.length === 0
        ? `No TXT records found matching ${expectedToken} on ${cleanDomain} (${lastError || 'NXDOMAIN'})`
        : `Found TXT records did not contain token ${expectedToken}`,
    };
  }

  async verifyTrafficRecord(domain: string, expectedTarget: string): Promise<TrafficVerificationResult> {
    const cleanDomain = domain.trim().toLowerCase();
    const resolvedTargets: string[] = [];

    // Check CNAME first
    try {
      const cnames = await dns.resolveCname(cleanDomain);
      for (const cname of cnames) {
        resolvedTargets.push(cname.toLowerCase());
        if (cname.toLowerCase() === expectedTarget.toLowerCase()) {
          return { pointed: true, resolvedTargets };
        }
      }
    } catch {
      // Not a CNAME or no CNAME records
    }

    // Check A records
    try {
      const ips = await dns.resolve4(cleanDomain);
      for (const ip of ips) {
        resolvedTargets.push(ip);
        if (ip === expectedTarget) {
          return { pointed: true, resolvedTargets };
        }
      }
    } catch (err: any) {
      if (resolvedTargets.length === 0) {
        return {
          pointed: false,
          resolvedTargets,
          error: `DNS resolution failed: ${err.message || String(err)}`,
        };
      }
    }

    return {
      pointed: false,
      resolvedTargets,
      error: `Domain ${cleanDomain} does not point to ${expectedTarget}`,
    };
  }
}
