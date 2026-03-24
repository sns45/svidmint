import type { Attestor } from '../attestor.js';

export interface CloudflareAttestorOptions {
  /** The Cloudflare Access JWT token. */
  accessJwt: string;
}

/**
 * CloudflareAttestor wraps a Cloudflare Access JWT for workload attestation.
 * The JWT is typically available via the CF-Access-JWT-Assertion header.
 */
export class CloudflareAttestor implements Attestor {
  private accessJwt: string;

  constructor(options: CloudflareAttestorOptions) {
    if (!options.accessJwt) {
      throw new Error('accessJwt is required');
    }
    this.accessJwt = options.accessJwt;
  }

  evidenceType(): string {
    return 'cf_access';
  }

  async gatherEvidence(): Promise<string> {
    return this.accessJwt;
  }
}
