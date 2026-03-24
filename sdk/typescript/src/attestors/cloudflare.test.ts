import { describe, it, expect } from 'vitest';
import { CloudflareAttestor } from './cloudflare.js';

describe('CloudflareAttestor', () => {
  it('returns cf_access as evidence type', () => {
    const attestor = new CloudflareAttestor({ accessJwt: 'some.jwt.token' });
    expect(attestor.evidenceType()).toBe('cf_access');
  });

  it('returns the access JWT as evidence', async () => {
    const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJjZiJ9.sig';
    const attestor = new CloudflareAttestor({ accessJwt: jwt });
    const evidence = await attestor.gatherEvidence();
    expect(evidence).toBe(jwt);
  });

  it('throws if accessJwt is empty', () => {
    expect(() => new CloudflareAttestor({ accessJwt: '' })).toThrow('accessJwt is required');
  });
});
