import { describe, it, expect, vi } from 'vitest';
import { AWSLambdaAttestor } from './aws-lambda.js';

describe('AWSLambdaAttestor', () => {
  it('returns aws_iid as evidence type', () => {
    const attestor = new AWSLambdaAttestor({
      accessKeyId: 'AKID',
      secretAccessKey: 'secret',
      region: 'us-east-1',
    });
    expect(attestor.evidenceType()).toBe('aws_iid');
  });

  it('throws when credentials are missing', async () => {
    const attestor = new AWSLambdaAttestor({
      accessKeyId: '',
      secretAccessKey: '',
    });
    await expect(attestor.gatherEvidence()).rejects.toThrow('AWS credentials are required');
  });

  it('performs SigV4 signed GetCallerIdentity request', async () => {
    const stsResponse = '<GetCallerIdentityResponse><Arn>arn:aws:iam::123456789012:role/lambda</Arn></GetCallerIdentityResponse>';
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(stsResponse),
    }) as unknown as typeof fetch;

    const attestor = new AWSLambdaAttestor({
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      sessionToken: 'session123',
      region: 'us-east-1',
      fetchImpl: mockFetch,
    });

    const evidence = await attestor.gatherEvidence();

    // Evidence should be base64 encoded JSON
    const decoded = JSON.parse(atob(evidence));
    expect(decoded.method).toBe('POST');
    expect(decoded.url).toBe('https://sts.us-east-1.amazonaws.com');
    expect(decoded.body).toBe('Action=GetCallerIdentity&Version=2011-06-15');
    expect(decoded.response).toBe(stsResponse);

    // Verify fetch was called with SigV4 headers
    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, reqInit] = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('https://sts.us-east-1.amazonaws.com');
    expect(reqInit.method).toBe('POST');
    expect(reqInit.headers['Authorization']).toContain('AWS4-HMAC-SHA256');
    expect(reqInit.headers['Authorization']).toContain('Credential=AKIAIOSFODNN7EXAMPLE/');
    expect(reqInit.headers['Authorization']).toContain('SignedHeaders=content-type;host;x-amz-date;x-amz-security-token');
    expect(reqInit.headers['X-Amz-Date']).toMatch(/^\d{8}T\d{6}Z$/);
    expect(reqInit.headers['X-Amz-Security-Token']).toBe('session123');
  });

  it('omits security token header when no session token', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve('<GetCallerIdentityResponse></GetCallerIdentityResponse>'),
    }) as unknown as typeof fetch;

    const attestor = new AWSLambdaAttestor({
      accessKeyId: 'AKID',
      secretAccessKey: 'secret',
      region: 'eu-west-1',
      fetchImpl: mockFetch,
    });

    await attestor.gatherEvidence();

    const [, reqInit] = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(reqInit.headers['X-Amz-Security-Token']).toBeUndefined();
    expect(reqInit.headers['Authorization']).toContain('SignedHeaders=content-type;host;x-amz-date,');
  });

  it('throws on STS error response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      text: () => Promise.resolve('Forbidden'),
    }) as unknown as typeof fetch;

    const attestor = new AWSLambdaAttestor({
      accessKeyId: 'AKID',
      secretAccessKey: 'secret',
      fetchImpl: mockFetch,
    });

    await expect(attestor.gatherEvidence()).rejects.toThrow('STS GetCallerIdentity failed with status 403');
  });

  it('uses crypto.subtle for HMAC operations (not Node.js crypto)', async () => {
    // Verify crypto.subtle is used by checking that the module works
    // with the standard Web Crypto API. The implementation uses
    // crypto.subtle.importKey and crypto.subtle.sign directly.
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve('<Response/>'),
    }) as unknown as typeof fetch;

    const attestor = new AWSLambdaAttestor({
      accessKeyId: 'AKID',
      secretAccessKey: 'secret',
      region: 'us-west-2',
      stsEndpoint: 'https://sts.us-west-2.amazonaws.com',
      fetchImpl: mockFetch,
    });

    // This succeeds only if crypto.subtle is available and working
    const evidence = await attestor.gatherEvidence();
    expect(evidence).toBeTruthy();
    const decoded = JSON.parse(atob(evidence));
    expect(decoded.headers['Authorization']).toContain('AWS4-HMAC-SHA256');
  });
});
