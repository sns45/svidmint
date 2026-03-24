import { describe, it, expect, vi } from 'vitest';
import { WorkloadIDClient } from './client.js';
import type { Attestor } from './attestor.js';

function mockAttestor(evidenceType = 'test_type', evidence = 'test_evidence'): Attestor {
  return {
    evidenceType: () => evidenceType,
    gatherEvidence: vi.fn().mockResolvedValue(evidence),
  };
}

function mockFetch(responseBody: unknown, ok = true, status = 200): typeof fetch {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    json: () => Promise.resolve(responseBody),
  }) as unknown as typeof fetch;
}

describe('WorkloadIDClient', () => {
  const server = 'https://svidmint.example.com';

  describe('attestJWT', () => {
    it('sends correct request and returns response', async () => {
      const expected = { spiffe_id: 'spiffe://example.com/workload', token: 'jwt.token.here', expires_at: '2026-04-01T00:00:00Z' };
      const fetchFn = mockFetch(expected);
      const attestor = mockAttestor('github_oidc', 'oidc_token_123');
      const client = new WorkloadIDClient({ server, attestor, fetchImpl: fetchFn });

      const result = await client.attestJWT({ audience: ['api.example.com'] });

      expect(result).toEqual(expected);
      expect(fetchFn).toHaveBeenCalledWith(`${server}/v1/attest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          evidence_type: 'github_oidc',
          evidence: 'oidc_token_123',
          svid_type: 'jwt',
          audience: ['api.example.com'],
        }),
      });
    });
  });

  describe('attestX509', () => {
    it('sends correct request without CSR', async () => {
      const expected = {
        spiffe_id: 'spiffe://example.com/workload',
        certificate: 'cert_pem',
        private_key: 'key_pem',
        bundle: 'bundle_pem',
        expires_at: '2026-04-01T00:00:00Z',
      };
      const fetchFn = mockFetch(expected);
      const attestor = mockAttestor('cf_access', 'cf_jwt');
      const client = new WorkloadIDClient({ server, attestor, fetchImpl: fetchFn });

      const result = await client.attestX509();

      expect(result).toEqual(expected);
      expect(fetchFn).toHaveBeenCalledWith(`${server}/v1/attest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          evidence_type: 'cf_access',
          evidence: 'cf_jwt',
          svid_type: 'x509',
          csr: undefined,
        }),
      });
    });

    it('sends correct request with CSR', async () => {
      const expected = {
        spiffe_id: 'spiffe://example.com/workload',
        certificate: 'cert_pem',
        private_key: '',
        bundle: 'bundle_pem',
        expires_at: '2026-04-01T00:00:00Z',
      };
      const fetchFn = mockFetch(expected);
      const attestor = mockAttestor();
      const client = new WorkloadIDClient({ server, attestor, fetchImpl: fetchFn });

      const result = await client.attestX509({ csr: 'csr_pem_data' });

      expect(result).toEqual(expected);
      const calledBody = JSON.parse((fetchFn as ReturnType<typeof vi.fn>).mock.calls[0][1].body);
      expect(calledBody.csr).toBe('csr_pem_data');
    });
  });

  describe('getBundle', () => {
    it('fetches bundle without trust domain', async () => {
      const expected = { trust_domain: 'example.com', x509_authorities: ['cert'], jwt_authorities: [] };
      const fetchFn = mockFetch(expected);
      const client = new WorkloadIDClient({ server, attestor: mockAttestor(), fetchImpl: fetchFn });

      const result = await client.getBundle();

      expect(result).toEqual(expected);
      expect(fetchFn).toHaveBeenCalledWith(`${server}/v1/bundle`);
    });

    it('fetches bundle with trust domain', async () => {
      const expected = { trust_domain: 'other.com', x509_authorities: [], jwt_authorities: [] };
      const fetchFn = mockFetch(expected);
      const client = new WorkloadIDClient({ server, attestor: mockAttestor(), fetchImpl: fetchFn });

      const result = await client.getBundle('other.com');

      expect(result).toEqual(expected);
      expect(fetchFn).toHaveBeenCalledWith(`${server}/v1/bundle?trust_domain=other.com`);
    });
  });

  describe('validate', () => {
    it('validates a JWT SVID', async () => {
      const expected = { valid: true, spiffe_id: 'spiffe://example.com/workload', expires_at: '2026-04-01T00:00:00Z' };
      const fetchFn = mockFetch(expected);
      const client = new WorkloadIDClient({ server, attestor: mockAttestor(), fetchImpl: fetchFn });

      const result = await client.validate('jwt', 'some.jwt.token');

      expect(result).toEqual(expected);
      expect(fetchFn).toHaveBeenCalledWith(`${server}/v1/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ svid_type: 'jwt', svid: 'some.jwt.token' }),
      });
    });
  });

  describe('error handling', () => {
    it('throws with error code on non-OK response', async () => {
      const fetchFn = mockFetch({ error: { code: 'ATTESTATION_FAILED', message: 'bad evidence' } }, false, 403);
      const client = new WorkloadIDClient({ server, attestor: mockAttestor(), fetchImpl: fetchFn });

      await expect(client.attestJWT({ audience: ['api'] })).rejects.toThrow('ATTESTATION_FAILED');
    });

    it('throws UNKNOWN_ERROR when error code is missing', async () => {
      const fetchFn = mockFetch({ error: {} }, false, 500);
      const client = new WorkloadIDClient({ server, attestor: mockAttestor(), fetchImpl: fetchFn });

      await expect(client.attestX509()).rejects.toThrow('UNKNOWN_ERROR');
    });

    it('throws UNKNOWN_ERROR for getBundle errors', async () => {
      const fetchFn = mockFetch({ error: { code: 'NOT_FOUND', message: 'no bundle' } }, false, 404);
      const client = new WorkloadIDClient({ server, attestor: mockAttestor(), fetchImpl: fetchFn });

      await expect(client.getBundle('missing.com')).rejects.toThrow('NOT_FOUND');
    });
  });
});
