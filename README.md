# svidmint

<p align="center">
  <img src="assets/marketing/poster.png" alt="svidmint poster" width="600" />
</p>

SPIFFE-compatible workload identity for serverless and edge environments.

## Problem

SPIFFE/SPIRE is the standard for workload identity, but it requires a persistent agent on every node that attests workloads via kernel level inspection over a Unix domain socket. Serverless platforms (AWS Lambda, Cloudflare Workers, Deno Deploy) do not allow long running daemons, do not expose Unix sockets, and abstract the OS entirely. svidmint fills this gap using platform native attestation (OIDC tokens, STS signed requests) instead of kernel inspection.

## Architecture

```
+-------------------------------------------------------------+
|                     svidmint Server                         |
|                                                             |
|  +--------------+  +---------------+  +-------------------+ |
|  | Attestation  |  | SPIFFE ID     |  | Certificate       | |
|  | Engine       |  | Mapper        |  | Authority (CA)    | |
|  |              |  |               |  |                   | |
|  | . AWS Lambda |  | Policy based  |  | . X.509 signing   | |
|  | . Cloudflare |  | mapping of    |  | . JWT signing     | |
|  | . Deno Deploy|  | platform      |  | . Trust bundle    | |
|  | . GitHub     |  | identity to   |  |   management      | |
|  |   Actions    |  | SPIFFE ID     |  | . SVID lifecycle  | |
|  +------+-------+  +------+--------+  +--------+----------+ |
|         |                 |                     |            |
|  +------+-----------------+---------------------+----------+ |
|  |                    Identity API                         | |
|  |  POST /v1/attest    Attestation + SVID issuance        | |
|  |  GET  /v1/bundle    Trust bundle retrieval              | |
|  |  POST /v1/validate  SVID validation                    | |
|  |  GET  /v1/jwks      JWKS for JWT verification          | |
|  |  GET  /v1/health    Health check                       | |
|  +---------------------------------------------------------+ |
+-----------------------------+-------------------------------+
                              | HTTPS
               +--------------+--------------+
        +------+------+             +--------+-----+
        | Workload A  |             | Workload B   |
        | (Lambda)    |             | (Worker)     |
        |             |             |              |
        | 1. Get STS  |             | 1. Get CF    |
        |    token    |             |    JWT       |
        | 2. /attest  |             | 2. /attest   |
        | 3. Get SVID |---- mTLS -->| 3. Verify    |
        | 4. Call B   |             |    A's SVID  |
        +-------------+             +--------------+
```

## Install

```bash
# Homebrew
brew install sns45/tap/svidmint

# Go
go install github.com/sns45/svidmint/cmd/svidmint@latest

# Docker
docker pull ghcr.io/sns45/svidmint:latest
```

## Quickstart

### 1. Initialize the CA

```bash
svidmint ca init --trust-domain example.org
```

### 2. Create a registration entry

```bash
svidmint entry create \
  --spiffe-id spiffe://example.org/workload/api \
  --attestor aws_sts \
  --selector "aws.account_id:123456789012" \
  --selector "aws.function_name:my-api" \
  --ttl 300
```

### 3. Start the server

```bash
svidmint server start --trust-domain example.org
```

Or with Docker:

```bash
docker run -p 8443:8443 ghcr.io/sns45/svidmint:latest server start \
  --trust-domain example.org
```

### 4. Attest a workload

```bash
curl -X POST https://localhost:8443/v1/attest \
  -H "Content-Type: application/json" \
  -d '{
    "evidence_type": "github_oidc",
    "evidence": "<base64-encoded-oidc-token>",
    "svid_type": "jwt",
    "audience": ["backend.example.org"]
  }'
```

## Configuration

svidmint loads configuration from (in order): defaults, config file (`.svidmint.yaml`), environment variables (`SMINT_` prefix).

```yaml
trust_domain: example.org

server:
  listen: ":8443"
  tls:
    cert_file: /etc/svidmint/server.crt
    key_file: /etc/svidmint/server.key

ca:
  type: self-signed
  key_type: ec-p256
  root_key_path: /etc/svidmint/root.key
  root_cert_path: /etc/svidmint/root.crt
  signing_ttl: 24h
  default_svid_ttl: 5m
  max_svid_ttl: 1h

storage:
  type: sqlite        # or "postgres"
  dsn: /var/lib/svidmint/svidmint.db

attestors:
  aws_lambda:
    enabled: true
    allowed_account_ids: ["123456789012"]
  cloudflare_workers:
    enabled: true
    teams:
      - name: myteam
        certs_url: https://myteam.cloudflareaccess.com/cdn-cgi/access/certs
  github_oidc:
    enabled: true
    allowed_repositories: ["myorg/*"]
  deno_oidc:
    enabled: true

metrics:
  enabled: true
  listen: ":9090"

federation:
  bundles:
    - trust_domain: k8s.example.org
      endpoint: https://spire-server:8443/v1/bundle
      type: https_web
      refresh_interval: 5m
```

## Supported Platforms

| Platform | Attestation Method | Evidence Type |
|---|---|---|
| AWS Lambda | STS `GetCallerIdentity` signed request | `aws_sts` |
| Cloudflare Workers | Cloudflare Access JWT | `cloudflare_workers` |
| GitHub Actions | OIDC token | `github_oidc` |
| Deno Deploy | OIDC token | `deno_oidc` |

### Extracted Claims

**AWS Lambda**: `aws.account_id`, `aws.arn`, `aws.region`, `aws.function_name`
**Cloudflare Workers**: `cf.team`, `cf.audience`, `cf.email`
**GitHub Actions**: `github.repository`, `github.repository_owner`, `github.sha`, `github.ref`, `github.workflow`, `github.environment`, `github.runner_environment`, `github.actor`
**Deno Deploy**: `deno.project` plus GitHub OIDC claims

## Registration Entries

Registration entries map platform claims to SPIFFE IDs. Selectors use `key:value` format with glob pattern support.

```yaml
# entries.yaml
entries:
  - spiffe_id: spiffe://example.org/workload/api
    attestor: aws_sts
    selectors:
      - "aws.account_id:123456789012"
      - "aws.function_name:my-api"
    ttl: 300

  - spiffe_id: spiffe://example.org/ci/deploy
    attestor: github_oidc
    selectors:
      - "github.repository:myorg/*"
      - "github.ref:refs/heads/main"
    ttl: 600
```

Load entries on server start: `svidmint server start --entries entries.yaml`

### Auto Registration

When `auto_register: true` is configured, attestation succeeds even without a matching entry. The SPIFFE ID is derived from the attestor name and sorted claim values: `spiffe://<domain>/<attestor>/<values...>`.

## CLI Reference

```bash
svidmint ca init      --trust-domain <d> [--key-type ec-p256|ec-p384] [--force]
svidmint ca rotate    --trust-domain <d>
svidmint ca export    [--format pem|der]

svidmint entry create --spiffe-id <id> --attestor <n> --selector <s> [--ttl <sec>]
svidmint entry list   [--attestor <n>]
svidmint entry show   --id <id>
svidmint entry update --id <id> [flags]
svidmint entry delete --id <id>

svidmint server start [--config] [--listen] [--trust-domain] [--entries]
svidmint server config

svidmint version
```

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/v1/attest` | POST | Submit platform evidence, receive SVID |
| `/v1/bundle` | GET | Retrieve trust bundle |
| `/v1/validate` | POST | Validate an issued SVID |
| `/v1/jwks` | GET | JSON Web Key Set for JWT verification |
| `/v1/health` | GET | Health check |

### POST /v1/attest

```json
{
  "evidence_type": "aws_sts",
  "evidence": "<base64-encoded-evidence>",
  "svid_type": "x509",
  "audience": ["optional-for-jwt"],
  "csr": "optional-pem-csr"
}
```

### Error Responses

All errors return `{"error": {"code": "<CODE>", "message": "<detail>"}}`:
- `INVALID_REQUEST` (400): malformed request or missing fields
- `ATTESTATION_FAILED` (401): platform evidence validation failed
- `NO_MATCHING_ENTRY` (403): no registration entry matches the attested claims
- `INTERNAL_ERROR` (500): server error

## Go SDK

The Go SDK provides `X509Source` and `JWTSource` implementing `go-spiffe/v2` interfaces, making them drop in replacements for `workloadapi.NewX509Source()`.

```go
import sdk "github.com/sns45/svidmint/sdk/go"

// X509Source: drop-in for go-spiffe/v2 workloadapi.X509Source
source, err := sdk.NewX509Source(ctx,
    sdk.WithServerURL("https://svidmint.example.org"),
    sdk.WithAttestor(sdk.AWSLambdaClientAttestor()),
)
defer source.Close()

svid, _ := source.GetX509SVID()
log.Printf("SPIFFE ID: %s", svid.ID)

// TLS helpers
resp, _ := client.AttestX509(ctx)
tlsCfg, _ := resp.TLSClientConfig()
```

### SDK Client Methods

```go
client, _ := sdk.New(sdk.WithServerURL(url), sdk.WithAttestor(attestor))
client.AttestX509(ctx)
client.AttestJWT(ctx, []string{"audience"})
client.GetBundle(ctx)
```

### Platform Attestors

```go
sdk.AWSLambdaClientAttestor()              // reads AWS env vars, signs STS request
sdk.CloudflareClientAttestor(accessJWT)     // wraps Cloudflare Access JWT
sdk.GitHubOIDCClientAttestor(audience)      // fetches from ACTIONS_ID_TOKEN_REQUEST_URL
```

## TypeScript SDK

Zero production dependencies. Uses only `fetch`, `crypto.subtle`, and `TextEncoder` (works in Workers, Deno, and browsers).

```bash
npm install @svidmint/sdk
```

```typescript
import { WorkloadIDClient, CloudflareAttestor } from '@svidmint/sdk';

const client = new WorkloadIDClient({
  server: 'https://svidmint.example.org',
  attestor: new CloudflareAttestor({
    accessJwt: request.headers.get('CF-Access-JWT-Assertion') ?? '',
  }),
});

const svid = await client.attestJWT({ audience: ['backend.example.org'] });
```

### Available Attestors

```typescript
new CloudflareAttestor({ accessJwt })
new AWSLambdaAttestor({ accessKeyId, secretAccessKey, sessionToken, region })
new GitHubOIDCAttestor({ audience })
```

## Federation with SPIRE

svidmint federates with SPIRE via trust bundle exchange, enabling cross domain mTLS between serverless workloads (svidmint) and Kubernetes workloads (SPIRE).

```yaml
# SPIRE server: federate with svidmint
federates_with:
  "example.org":
    bundle_endpoint:
      address: "svidmint.example.org"
      port: 8443
      profile: "https_web"
```

```yaml
# svidmint: federate with SPIRE
federation:
  bundles:
    - trust_domain: k8s.example.org
      endpoint: https://spire-server:8443/v1/bundle
      type: https_web
      refresh_interval: 5m
```

## SVID Specification Compliance

**X.509 SVIDs**: URI SAN with SPIFFE ID, `CA:FALSE`, `DigitalSignature + KeyEncipherment`, `ServerAuth + ClientAuth`, ECDSA P-256, ECDSAWithSHA256. Chain: `[leaf, intermediate]`. Validated with `go-spiffe/v2` `x509svid.Verify`.

**JWT SVIDs**: ES256, `sub` = SPIFFE ID, `aud`, `exp`, `iat`, `jti`. No `iss` claim per SPIFFE spec. Validated with `go-spiffe/v2` `jwtsvid.ParseAndValidate`.

**Lifetime bounding**: `min(requestedTTL, entryTTL, platformTokenRemaining, globalMaxTTL)`.

## Observability

Prometheus metrics on a separate port (default `:9090`):
- `workload_id_attestation_total{attestor, status}`
- `workload_id_attestation_duration_seconds{attestor}`
- `workload_id_svid_issued_total{svid_type, attestor}`
- `workload_id_svid_validated_total{svid_type, valid}`
- `workload_id_active_entries`

Structured JSON logging via zap.

## Deployment

### Docker

```bash
docker run -v /etc/svidmint:/etc/svidmint ghcr.io/sns45/svidmint:latest \
  server start --config /etc/svidmint/config.yaml
```

### Kubernetes

Manifests in `deploy/kubernetes/` (Deployment, Service, ConfigMap).

```bash
kubectl apply -f deploy/kubernetes/
```

## Development

```bash
make build    # build binary with version injection
make test     # go test -race ./...
make lint     # golangci-lint
make install  # go install
make clean    # rm -rf bin/

# Integration tests
CGO_ENABLED=1 go test -tags integration -v ./internal/

# TypeScript SDK
cd sdk/typescript && npm install && npm test
```

## Project Structure

```
cmd/svidmint/          CLI entrypoint
internal/
  cli/                 Cobra commands
  config/              Viper configuration
  ca/                  Certificate authority, federation
  attestor/            Platform attestation plugins
  entry/               Registration entries, storage
  mapper/              Auto-registration ID derivation
  server/              HTTP server, API handlers
sdk/
  go/                  Go SDK (X509Source, JWTSource, TLS helpers)
  typescript/          TypeScript SDK (@svidmint/sdk)
deploy/
  docker/              Dockerfile
  kubernetes/          K8s manifests
```

## Contributing

Contributions welcome. Please open an issue first to discuss changes.

1. Fork the repository
2. Create a feature branch
3. Write tests (every `.go` file with logic gets a `_test.go` file)
4. `make test && make lint`
5. Submit a pull request

## License

Apache 2.0. See [LICENSE](LICENSE).
