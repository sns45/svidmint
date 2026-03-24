package attestor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// CloudflareTeamConfig holds configuration for a single Cloudflare Access team.
type CloudflareTeamConfig struct {
	Name     string
	CertsURL string
}

// CloudflareWorkersAttestorConfig is the configuration for the Cloudflare Workers attestor.
type CloudflareWorkersAttestorConfig struct {
	Teams []CloudflareTeamConfig
}

type cachedJWKS struct {
	keys      jose.JSONWebKeySet
	fetchedAt time.Time
}

// CloudflareWorkersAttestor validates Cloudflare Access JWTs for workload attestation.
type CloudflareWorkersAttestor struct {
	config     CloudflareWorkersAttestorConfig
	httpClient *http.Client

	mu       sync.RWMutex
	keyCache map[string]*cachedJWKS // keyed by certs URL
}

const jwksCacheTTL = 5 * time.Minute

// NewCloudflareWorkersAttestor creates a new Cloudflare Workers attestor.
func NewCloudflareWorkersAttestor(cfg CloudflareWorkersAttestorConfig) *CloudflareWorkersAttestor {
	return &CloudflareWorkersAttestor{
		config:     cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keyCache:   make(map[string]*cachedJWKS),
	}
}

// Name returns the attestor name.
func (a *CloudflareWorkersAttestor) Name() string {
	return "cloudflare_workers"
}

// CanAttest returns true if the evidence type is "cloudflare_workers".
func (a *CloudflareWorkersAttestor) CanAttest(evidenceType string) bool {
	return evidenceType == "cloudflare_workers"
}

type cloudflareEvidence struct {
	AccessJWT string `json:"access_jwt"`
}

type cloudflareClaims struct {
	Issuer   string           `json:"iss"`
	Audience jwt.Audience     `json:"aud"`
	Subject  string           `json:"sub"`
	Email    string           `json:"email"`
	Expiry   *jwt.NumericDate `json:"exp"`
	IssuedAt *jwt.NumericDate `json:"iat"`
	Type     string           `json:"type"`
}

// Attest validates Cloudflare Workers evidence and returns attestation claims.
func (a *CloudflareWorkersAttestor) Attest(ctx context.Context, evidence []byte) (*AttestationResult, error) {
	var ev cloudflareEvidence
	if err := json.Unmarshal(evidence, &ev); err != nil {
		return nil, fmt.Errorf("failed to parse cloudflare workers evidence: %w", err)
	}
	if ev.AccessJWT == "" {
		return nil, fmt.Errorf("cloudflare workers evidence missing access_jwt")
	}

	// Parse the JWT without verification first to extract the issuer for team matching
	tok, err := jwt.ParseSigned(ev.AccessJWT, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("failed to parse access JWT: %w", err)
	}

	// Extract unverified claims to determine which team this belongs to
	var unverified cloudflareClaims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, fmt.Errorf("failed to extract unverified claims: %w", err)
	}

	// Match issuer to a configured team
	team, err := a.matchTeam(unverified.Issuer)
	if err != nil {
		return nil, err
	}

	// Fetch JWKS for this team
	jwks, err := a.fetchJWKS(ctx, team.CertsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS for team %s: %w", team.Name, err)
	}

	// Verify the JWT signature against the fetched keys
	var verified cloudflareClaims
	if err := tok.Claims(jwks, &verified); err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	// Validate expiry
	now := time.Now()
	if verified.Expiry != nil && verified.Expiry.Time().Before(now) {
		return nil, fmt.Errorf("JWT has expired (exp: %s)", verified.Expiry.Time())
	}

	// Build audience string (join multiple audiences with comma)
	audience := ""
	if len(verified.Audience) > 0 {
		audience = strings.Join(verified.Audience, ",")
	}

	result := &AttestationResult{
		Claims: map[string]string{
			"cf.team":     team.Name,
			"cf.audience": audience,
			"cf.email":    verified.Email,
		},
		RawIdentity: ev.AccessJWT,
	}
	if verified.Expiry != nil {
		result.ExpiresAt = verified.Expiry.Time()
	}

	return result, nil
}

// matchTeam finds the configured team matching the JWT issuer.
func (a *CloudflareWorkersAttestor) matchTeam(issuer string) (*CloudflareTeamConfig, error) {
	for i := range a.config.Teams {
		team := &a.config.Teams[i]
		expectedIssuer := fmt.Sprintf("https://%s.cloudflareaccess.com", team.Name)
		if issuer == expectedIssuer {
			return team, nil
		}
	}
	return nil, fmt.Errorf("no configured team matches JWT issuer %q", issuer)
}

// fetchJWKS retrieves the JWKS from the given URL, using a cache with 5 minute TTL.
func (a *CloudflareWorkersAttestor) fetchJWKS(ctx context.Context, certsURL string) (*jose.JSONWebKeySet, error) {
	a.mu.RLock()
	cached, ok := a.keyCache[certsURL]
	a.mu.RUnlock()

	if ok && time.Since(cached.fetchedAt) < jwksCacheTTL {
		return &cached.keys, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certsURL, nil)
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
		return nil, fmt.Errorf("failed to parse JWKS response: %w", err)
	}

	a.mu.Lock()
	a.keyCache[certsURL] = &cachedJWKS{
		keys:      jwks,
		fetchedAt: time.Now(),
	}
	a.mu.Unlock()

	return &jwks, nil
}
