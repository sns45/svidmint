import type { Attestor } from '../attestor.js';

export interface AWSLambdaAttestorOptions {
  /** AWS region (e.g. "us-east-1"). Defaults to AWS_REGION or AWS_DEFAULT_REGION env var. */
  region?: string;
  /** Override for STS endpoint. Defaults to https://sts.{region}.amazonaws.com. */
  stsEndpoint?: string;
  /** AWS access key ID. Defaults to AWS_ACCESS_KEY_ID env var. */
  accessKeyId?: string;
  /** AWS secret access key. Defaults to AWS_SECRET_ACCESS_KEY env var. */
  secretAccessKey?: string;
  /** AWS session token. Defaults to AWS_SESSION_TOKEN env var. */
  sessionToken?: string;
  /** Custom fetch implementation for testing. */
  fetchImpl?: typeof fetch;
}

/**
 * AWSLambdaAttestor performs SigV4 signed GetCallerIdentity requests
 * using Web Crypto API (crypto.subtle) for HMAC and SHA operations.
 * Works in Workers, Deno, and any environment with Web Crypto support.
 */
export class AWSLambdaAttestor implements Attestor {
  private region: string;
  private stsEndpoint: string;
  private accessKeyId: string;
  private secretAccessKey: string;
  private sessionToken: string;
  private fetchImpl: typeof fetch;

  constructor(options: AWSLambdaAttestorOptions = {}) {
    this.region = options.region || getEnv('AWS_REGION') || getEnv('AWS_DEFAULT_REGION') || 'us-east-1';
    this.stsEndpoint = options.stsEndpoint || `https://sts.${this.region}.amazonaws.com`;
    this.accessKeyId = options.accessKeyId || getEnv('AWS_ACCESS_KEY_ID') || '';
    this.secretAccessKey = options.secretAccessKey || getEnv('AWS_SECRET_ACCESS_KEY') || '';
    this.sessionToken = options.sessionToken || getEnv('AWS_SESSION_TOKEN') || '';
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  evidenceType(): string {
    return 'aws_iid';
  }

  async gatherEvidence(): Promise<string> {
    if (!this.accessKeyId || !this.secretAccessKey) {
      throw new Error('AWS credentials are required (accessKeyId and secretAccessKey)');
    }

    const now = new Date();
    const dateStamp = formatDate(now);
    const amzDate = formatAmzDate(now);
    const host = new URL(this.stsEndpoint).host;
    const requestBody = 'Action=GetCallerIdentity&Version=2011-06-15';
    const bodyHash = await sha256(requestBody);

    const canonicalHeaders = [
      `content-type:application/x-www-form-urlencoded`,
      `host:${host}`,
      `x-amz-date:${amzDate}`,
      ...(this.sessionToken ? [`x-amz-security-token:${this.sessionToken}`] : []),
    ].join('\n') + '\n';

    const signedHeadersList = [
      'content-type',
      'host',
      'x-amz-date',
      ...(this.sessionToken ? ['x-amz-security-token'] : []),
    ];
    const signedHeaders = signedHeadersList.join(';');

    const canonicalRequest = [
      'POST',
      '/',
      '',
      canonicalHeaders,
      signedHeaders,
      bodyHash,
    ].join('\n');

    const credentialScope = `${dateStamp}/${this.region}/sts/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      await sha256(canonicalRequest),
    ].join('\n');

    const signingKey = await deriveSigningKey(this.secretAccessKey, dateStamp, this.region, 'sts');
    const signature = hexEncode(await hmacSHA256(signingKey, stringToSign));

    const authorization = `AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Amz-Date': amzDate,
      'Authorization': authorization,
    };
    if (this.sessionToken) {
      headers['X-Amz-Security-Token'] = this.sessionToken;
    }

    const resp = await this.fetchImpl(this.stsEndpoint, {
      method: 'POST',
      headers,
      body: requestBody,
    });

    if (!resp.ok) {
      throw new Error(`STS GetCallerIdentity failed with status ${resp.status}`);
    }

    const responseText = await resp.text();

    // Return base64 encoded signed request metadata so the server can verify
    const evidence = {
      method: 'POST',
      url: this.stsEndpoint,
      headers,
      body: requestBody,
      response: responseText,
    };

    return btoa(JSON.stringify(evidence));
  }
}

/** HMAC-SHA256 using Web Crypto API. */
async function hmacSHA256(key: ArrayBuffer, data: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
}

/** SHA-256 hash using Web Crypto API, returned as hex string. */
async function sha256(data: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return hexEncode(hash);
}

/** Derive SigV4 signing key through a chain of HMAC operations. */
async function deriveSigningKey(
  secretKey: string,
  dateStamp: string,
  region: string,
  service: string,
): Promise<ArrayBuffer> {
  const kDate = await hmacSHA256(new TextEncoder().encode(`AWS4${secretKey}`).buffer, dateStamp);
  const kRegion = await hmacSHA256(kDate, region);
  const kService = await hmacSHA256(kRegion, service);
  return hmacSHA256(kService, 'aws4_request');
}

/** Encode ArrayBuffer as lowercase hex string. */
function hexEncode(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Format date as YYYYMMDD. */
function formatDate(date: Date): string {
  return date.toISOString().slice(0, 10).replace(/-/g, '');
}

/** Format date as YYYYMMDD'T'HHMMSS'Z'. */
function formatAmzDate(date: Date): string {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
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
