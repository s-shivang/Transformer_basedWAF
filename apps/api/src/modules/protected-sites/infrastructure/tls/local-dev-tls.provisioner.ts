import { Injectable } from '@nestjs/common';
import {
  ITlsProvisioner,
  TlsProvisionResult,
  TlsStatusResult,
} from '../../domain/tls-provisioner.interface';
import { TlsStatus } from '../../domain/protected-site.entity';

@Injectable()
export class LocalDevTlsProvisioner implements ITlsProvisioner {
  private failedDomains: Set<string> = new Set();

  public setDomainFailure(domain: string, fail = true) {
    const key = domain.trim().toLowerCase();
    if (fail) {
      this.failedDomains.add(key);
    } else {
      this.failedDomains.delete(key);
    }
  }

  public clear() {
    this.failedDomains.clear();
  }

  async provisionCertificate(domain: string): Promise<TlsProvisionResult> {
    const cleanDomain = domain.trim().toLowerCase();

    if (this.failedDomains.has(cleanDomain) || cleanDomain.includes('fail-tls')) {
      return {
        provisioned: false,
        issuer: 'local-dev-acme',
        expiresAt: new Date(),
        error: `LocalDev: TLS certificate provisioning failed for domain ${cleanDomain}`,
      };
    }

    // Deterministic 90-day validity for local-dev / zero-spend operation
    const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);

    return {
      provisioned: true,
      issuer: 'local-dev-acme',
      expiresAt,
    };
  }

  async checkCertificateStatus(domain: string): Promise<TlsStatusResult> {
    const cleanDomain = domain.trim().toLowerCase();
    if (this.failedDomains.has(cleanDomain)) {
      return { status: TlsStatus.FAILED };
    }
    const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
    return {
      status: TlsStatus.PROVISIONED,
      expiresAt,
    };
  }
}

/**
 * Adapter placeholder for future production Let's Encrypt / ACME integration
 * (HTTP-01 / DNS-01 challenge automation via certbot / acme-client).
 */
export class AcmeTlsProvisioner implements ITlsProvisioner {
  async provisionCertificate(domain: string): Promise<TlsProvisionResult> {
    throw new Error(`Production ACME provisioner not configured. Domain: ${domain}`);
  }

  async checkCertificateStatus(domain: string): Promise<TlsStatusResult> {
    throw new Error(`Production ACME provisioner not configured. Domain: ${domain}`);
  }
}
