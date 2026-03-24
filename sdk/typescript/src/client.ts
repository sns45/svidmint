import type { Attestor } from './attestor.js';
import type {
  X509SVIDResponse,
  JWTSVIDResponse,
  BundleResponse,
  ValidateResponse,
} from './types.js';

export interface WorkloadIDClientOptions {
  server: string;
  attestor: Attestor;
  fetchImpl?: typeof fetch;
}

export class WorkloadIDClient {
  private server: string;
  private attestor: Attestor;
  private fetchImpl: typeof fetch;

  constructor(options: WorkloadIDClientOptions) {
    this.server = options.server;
    this.attestor = options.attestor;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async attestX509(options?: { csr?: string }): Promise<X509SVIDResponse> {
    const evidence = await this.attestor.gatherEvidence();
    const body = {
      evidence_type: this.attestor.evidenceType(),
      evidence: evidence,
      svid_type: 'x509',
      csr: options?.csr,
    };
    return this.post<X509SVIDResponse>('/v1/attest', body);
  }

  async attestJWT(options: { audience: string[] }): Promise<JWTSVIDResponse> {
    const evidence = await this.attestor.gatherEvidence();
    const body = {
      evidence_type: this.attestor.evidenceType(),
      evidence: evidence,
      svid_type: 'jwt',
      audience: options.audience,
    };
    return this.post<JWTSVIDResponse>('/v1/attest', body);
  }

  async getBundle(trustDomain?: string): Promise<BundleResponse> {
    const url = trustDomain
      ? `${this.server}/v1/bundle?trust_domain=${encodeURIComponent(trustDomain)}`
      : `${this.server}/v1/bundle`;
    const resp = await this.fetchImpl(url);
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error?.code || 'UNKNOWN_ERROR');
    }
    return resp.json();
  }

  async validate(svidType: 'x509' | 'jwt', svid: string): Promise<ValidateResponse> {
    return this.post<ValidateResponse>('/v1/validate', { svid_type: svidType, svid });
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const resp = await this.fetchImpl(`${this.server}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error?.code || 'UNKNOWN_ERROR');
    }
    return resp.json();
  }
}
