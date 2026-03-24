package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// cloudflareAttestor wraps a Cloudflare Access JWT for attestation.
type cloudflareAttestor struct {
	accessJWT string
}

// CloudflareClientAttestor creates a ClientAttestor that presents a Cloudflare Access JWT.
func CloudflareClientAttestor(accessJWT string) ClientAttestor {
	return &cloudflareAttestor{accessJWT: accessJWT}
}

func (a *cloudflareAttestor) EvidenceType() string { return "cloudflare_workers" }

func (a *cloudflareAttestor) GatherEvidence(ctx context.Context) ([]byte, error) {
	return json.Marshal(map[string]string{"access_jwt": a.accessJWT})
}

// githubOIDCAttestor fetches an OIDC token from GitHub Actions runtime.
type githubOIDCAttestor struct {
	audience string
}

// GitHubOIDCClientAttestor creates a ClientAttestor that fetches a GitHub Actions OIDC token.
func GitHubOIDCClientAttestor(audience string) ClientAttestor {
	return &githubOIDCAttestor{audience: audience}
}

func (a *githubOIDCAttestor) EvidenceType() string { return "github_oidc" }

func (a *githubOIDCAttestor) GatherEvidence(ctx context.Context) ([]byte, error) {
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqToken == "" {
		return nil, fmt.Errorf("GitHub Actions OIDC environment not available")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL+"&audience="+a.audience, nil)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+reqToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading OIDC response: %w", err)
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing OIDC response: %w", err)
	}

	return json.Marshal(map[string]string{"oidc_token": result.Value})
}

// awsLambdaAttestor signs an AWS STS GetCallerIdentity request for attestation.
type awsLambdaAttestor struct{}

// AWSLambdaClientAttestor creates a ClientAttestor that uses AWS STS GetCallerIdentity.
func AWSLambdaClientAttestor() ClientAttestor {
	return &awsLambdaAttestor{}
}

func (a *awsLambdaAttestor) EvidenceType() string { return "aws_sts" }

func (a *awsLambdaAttestor) GatherEvidence(ctx context.Context) ([]byte, error) {
	// Read AWS credentials from environment and sign STS GetCallerIdentity request.
	// This is a stub; full SigV4 signing will be implemented when the AWS attestor
	// server side is complete.
	return nil, fmt.Errorf("AWS STS signing not implemented in SDK client")
}
