import { TlsStatus } from './protected-site.entity';

export const TLS_PROVISIONER = Symbol('TLS_PROVISIONER');

export interface TlsProvisionResult {
  provisioned: boolean;
  issuer: string;
  expiresAt: Date;
  error?: string;
}

export interface TlsStatusResult {
  status: TlsStatus;
  expiresAt?: Date;
}

export interface ITlsProvisioner {
  provisionCertificate(domain: string): Promise<TlsProvisionResult>;
  checkCertificateStatus(domain: string): Promise<TlsStatusResult>;
}
