import type { Attestor } from '../attestor.js';

export interface GitHubOIDCAttestorOptions {
  /** The audience for the OIDC token request. */
  audience?: string;
  /** Override ACTIONS_ID_TOKEN_REQUEST_URL for testing. */
  requestUrl?: string;
  /** Override ACTIONS_ID_TOKEN_REQUEST_TOKEN for testing. */
  requestToken?: string;
  /** Custom fetch implementation for testing. */
  fetchImpl?: typeof fetch;
}

/**
 * GitHubOIDCAttestor fetches an OIDC token from the GitHub Actions
 * environment using the ACTIONS_ID_TOKEN_REQUEST_URL and
 * ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variables.
 */
export class GitHubOIDCAttestor implements Attestor {
  private audience?: string;
  private requestUrl: string;
  private requestToken: string;
  private fetchImpl: typeof fetch;

  constructor(options: GitHubOIDCAttestorOptions = {}) {
    this.audience = options.audience;
    this.requestUrl = options.requestUrl || getEnv('ACTIONS_ID_TOKEN_REQUEST_URL') || '';
    this.requestToken = options.requestToken || getEnv('ACTIONS_ID_TOKEN_REQUEST_TOKEN') || '';
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  evidenceType(): string {
    return 'github_oidc';
  }

  async gatherEvidence(): Promise<string> {
    if (!this.requestUrl || !this.requestToken) {
      throw new Error(
        'GitHub OIDC environment not available. Ensure ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN are set.',
      );
    }

    const url = this.audience
      ? `${this.requestUrl}&audience=${encodeURIComponent(this.audience)}`
      : this.requestUrl;

    const resp = await this.fetchImpl(url, {
      headers: {
        Authorization: `bearer ${this.requestToken}`,
        Accept: 'application/json; api-version=2.0',
      },
    });

    if (!resp.ok) {
      throw new Error(`GitHub OIDC token request failed with status ${resp.status}`);
    }

    const data = (await resp.json()) as { value: string };
    return data.value;
  }
}

/** Safe environment variable access that works across runtimes. */
function getEnv(name: string): string | undefined {
  try {
    if (typeof globalThis !== 'undefined' && 'process' in globalThis) {
      return (globalThis as Record<string, unknown>).process
        ? ((globalThis as Record<string, unknown>).process as Record<string, Record<string, string>>).env?.[name]
        : undefined;
    }
  } catch {
    // Environment variable access not available
  }
  return undefined;
}
