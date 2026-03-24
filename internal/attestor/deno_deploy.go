package attestor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	denoEvidenceType   = "deno_oidc"
	denoDefaultIssuer  = "https://oidc.deno.com"
)

// DenoDeployAttestorConfig holds configuration for the Deno Deploy attestor.
type DenoDeployAttestorConfig struct {
	AllowedIssuers []string
	JWKSURLOverride string
}

// DenoDeployAttestor validates Deno Deploy OIDC tokens.
type DenoDeployAttestor struct {
	config     DenoDeployAttestorConfig
	httpClient *http.Client
}

// NewDenoDeployAttestor creates a new Deno Deploy attestor.
func NewDenoDeployAttestor(config DenoDeployAttestorConfig) *DenoDeployAttestor {
	if len(config.AllowedIssuers) == 0 {
		config.AllowedIssuers = []string{denoDefaultIssuer}
	}
	return &DenoDeployAttestor{
		config:     config,
		httpClient: http.DefaultClient,
	}
}

func (a *DenoDeployAttestor) Name() string {
	return denoEvidenceType
}

func (a *DenoDeployAttestor) CanAttest(evidenceType string) bool {
	return evidenceType == denoEvidenceType
}

type denoOIDCEvidence struct {
	Token string `json:"token"`
}

type denoClaims struct {
	Issuer      string           `json:"iss"`
	Subject     string           `json:"sub"`
	Expiry      *jwt.NumericDate `json:"exp"`
	IssuedAt    *jwt.NumericDate `json:"iat"`
	DenoProject string           `json:"deno.project,omitempty"`
	Repository  string           `json:"repository,omitempty"`
}

func (a *DenoDeployAttestor) Attest(ctx context.Context, evidence []byte) (*AttestationResult, error) {
	var ev denoOIDCEvidence
	if err := json.Unmarshal(evidence, &ev); err != nil {
		return nil, fmt.Errorf("invalid evidence format: %w", err)
	}
	if ev.Token == "" {
		return nil, fmt.Errorf("missing token in evidence")
	}

	parsed, err := jwt.ParseSigned(ev.Token, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Extract claims without verification first to get issuer for JWKS lookup
	var unverified denoClaims
	if err := parsed.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	if !a.isAllowedIssuer(unverified.Issuer) {
		return nil, fmt.Errorf("untrusted issuer: %s", unverified.Issuer)
	}

	jwks, err := a.fetchJWKS(ctx, unverified.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	var verified denoClaims
	if err := parsed.Claims(jwks, &verified); err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	now := time.Now()
	if verified.Expiry != nil && verified.Expiry.Time().Before(now) {
		return nil, fmt.Errorf("token expired at %s", verified.Expiry.Time())
	}

	claims := map[string]string{
		"iss": verified.Issuer,
		"sub": verified.Subject,
	}
	if verified.DenoProject != "" {
		claims["deno.project"] = verified.DenoProject
	}
	if verified.Repository != "" {
		claims["repository"] = verified.Repository
	}

	expiresAt := now.Add(1 * time.Hour)
	if verified.Expiry != nil {
		expiresAt = verified.Expiry.Time()
	}

	return &AttestationResult{
		Claims:      claims,
		ExpiresAt:   expiresAt,
		RawIdentity: verified.Subject,
	}, nil
}

func (a *DenoDeployAttestor) isAllowedIssuer(issuer string) bool {
	for _, allowed := range a.config.AllowedIssuers {
		if allowed == issuer {
			return true
		}
	}
	return false
}

func (a *DenoDeployAttestor) fetchJWKS(ctx context.Context, issuer string) (*jose.JSONWebKeySet, error) {
	jwksURL := issuer + "/.well-known/jwks.json"
	if a.config.JWKSURLOverride != "" {
		jwksURL = a.config.JWKSURLOverride
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return &jwks, nil
}
