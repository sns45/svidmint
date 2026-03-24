export type { Attestor } from './attestor.js';
export type {
  X509SVIDResponse,
  JWTSVIDResponse,
  BundleResponse,
  JWTAuthority,
  ValidateResponse,
  ErrorResponse,
} from './types.js';
export { WorkloadIDClient } from './client.js';
export type { WorkloadIDClientOptions } from './client.js';
export { CloudflareAttestor } from './attestors/cloudflare.js';
export type { CloudflareAttestorOptions } from './attestors/cloudflare.js';
export { AWSLambdaAttestor } from './attestors/aws-lambda.js';
export type { AWSLambdaAttestorOptions } from './attestors/aws-lambda.js';
export { GitHubOIDCAttestor } from './attestors/github-oidc.js';
export type { GitHubOIDCAttestorOptions } from './attestors/github-oidc.js';
