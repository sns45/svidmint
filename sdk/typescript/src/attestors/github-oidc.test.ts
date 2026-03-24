import { describe, it, expect, vi } from 'vitest';
import { GitHubOIDCAttestor } from './github-oidc.js';

describe('GitHubOIDCAttestor', () => {
  it('returns github_oidc as evidence type', () => {
    const attestor = new GitHubOIDCAttestor({
      requestUrl: 'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
      requestToken: 'gha_token',
    });
    expect(attestor.evidenceType()).toBe('github_oidc');
  });

  it('fetches OIDC token from GitHub Actions', async () => {
    const oidcToken = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOm9yZy9yZXBvOnJlZjpyZWZzL2hlYWRzL21haW4ifQ.sig';
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ value: oidcToken }),
    }) as unknown as typeof fetch;

    const attestor = new GitHubOIDCAttestor({
      requestUrl: 'https://vstoken.actions.githubusercontent.com/.identity?api-version=2.0',
      requestToken: 'gha_abc123',
      fetchImpl: mockFetch,
    });

    const evidence = await attestor.gatherEvidence();
    expect(evidence).toBe(oidcToken);

    expect(mockFetch).toHaveBeenCalledWith(
      'https://vstoken.actions.githubusercontent.com/.identity?api-version=2.0',
      {
        headers: {
          Authorization: 'bearer gha_abc123',
          Accept: 'application/json; api-version=2.0',
        },
      },
    );
  });

  it('appends audience parameter when specified', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ value: 'token' }),
    }) as unknown as typeof fetch;

    const attestor = new GitHubOIDCAttestor({
      requestUrl: 'https://vstoken.actions.githubusercontent.com/.identity?api-version=2.0',
      requestToken: 'gha_token',
      audience: 'svidmint.example.com',
      fetchImpl: mockFetch,
    });

    await attestor.gatherEvidence();

    const calledUrl = (mockFetch as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(calledUrl).toBe(
      'https://vstoken.actions.githubusercontent.com/.identity?api-version=2.0&audience=svidmint.example.com',
    );
  });

  it('throws when environment variables are not set', async () => {
    const attestor = new GitHubOIDCAttestor({
      requestUrl: '',
      requestToken: '',
    });

    await expect(attestor.gatherEvidence()).rejects.toThrow('GitHub OIDC environment not available');
  });

  it('throws on non-OK response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
    }) as unknown as typeof fetch;

    const attestor = new GitHubOIDCAttestor({
      requestUrl: 'https://vstoken.actions.githubusercontent.com/.identity',
      requestToken: 'bad_token',
      fetchImpl: mockFetch,
    });

    await expect(attestor.gatherEvidence()).rejects.toThrow('failed with status 401');
  });
});
