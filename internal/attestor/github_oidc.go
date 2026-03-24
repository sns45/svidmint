package attestor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	defaultGitHubIssuer = "https://token.actions.githubusercontent.com"
	jwksCacheDuration   = 1 * time.Hour
)

// GitHubOIDCAttestorConfig holds configuration for the GitHub Actions OIDC attestor.
type GitHubOIDCAttestorConfig struct {
	AllowedRepositories  []string
	Issuer               string // default "https://token.actions.githubusercontent.com"
	JWKSEndpointOverride string // for testing
}

// GitHubOIDCAttestor validates GitHub Actions OIDC tokens and extracts claims.
type GitHubOIDCAttestor struct {
	config     GitHubOIDCAttestorConfig
	httpClient *http.Client

	jwksMu      sync.Mutex
	cachedJWKS  *jose.JSONWebKeySet
	jwksFetched time.Time
}

// NewGitHubOIDCAttestor creates a new GitHub Actions OIDC attestor.
func NewGitHubOIDCAttestor(config GitHubOIDCAttestorConfig) *GitHubOIDCAttestor {
	if config.Issuer == "" {
		config.Issuer = defaultGitHubIssuer
	}
	return &GitHubOIDCAttestor{
		config:     config,
		httpClient: http.DefaultClient,
	}
}

func (a *GitHubOIDCAttestor) Name() string {
	return "github_oidc"
}

func (a *GitHubOIDCAttestor) CanAttest(evidenceType string) bool {
	return evidenceType == "github_oidc"
}

type githubOIDCEvidence struct {
	OIDCToken string `json:"oidc_token"`
}

type githubOIDCClaims struct {
	jwt.Claims
	Repository        string `json:"repository"`
	RepositoryOwner   string `json:"repository_owner"`
	SHA               string `json:"sha"`
	Ref               string `json:"ref"`
	Workflow          string `json:"workflow"`
	Environment       string `json:"environment"`
	RunnerEnvironment string `json:"runner_environment"`
	Actor             string `json:"actor"`
}

func (a *GitHubOIDCAttestor) Attest(ctx context.Context, evidence []byte) (*AttestationResult, error) {
	var ev githubOIDCEvidence
	if err := json.Unmarshal(evidence, &ev); err != nil {
		return nil, fmt.Errorf("github_oidc: failed to parse evidence: %w", err)
	}
	if ev.OIDCToken == "" {
		return nil, fmt.Errorf("github_oidc: missing oidc_token in evidence")
	}

	tok, err := jwt.ParseSigned(ev.OIDCToken, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("github_oidc: failed to parse JWT: %w", err)
	}

	jwks, err := a.fetchJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("github_oidc: failed to fetch JWKS: %w", err)
	}

	var claims githubOIDCClaims
	if err := tok.Claims(jwks, &claims); err != nil {
		return nil, fmt.Errorf("github_oidc: failed to verify JWT signature: %w", err)
	}

	// Validate standard claims
	expected := jwt.Expected{
		Issuer: a.config.Issuer,
		Time:   time.Now(),
	}
	if err := claims.Claims.Validate(expected); err != nil {
		// Provide more specific error messages
		if claims.Claims.Issuer != a.config.Issuer {
			return nil, fmt.Errorf("github_oidc: issuer mismatch: got %q, expected %q", claims.Claims.Issuer, a.config.Issuer)
		}
		return nil, fmt.Errorf("github_oidc: token validation failed (check exp/nbf): %w", err)
	}

	// Validate repository against allowed patterns
	if err := a.validateRepository(claims.Repository); err != nil {
		return nil, err
	}

	expiresAt := time.Time{}
	if claims.Claims.Expiry != nil {
		expiresAt = claims.Claims.Expiry.Time()
	}

	return &AttestationResult{
		Claims: map[string]string{
			"github.repository":         claims.Repository,
			"github.repository_owner":   claims.RepositoryOwner,
			"github.sha":                claims.SHA,
			"github.ref":                claims.Ref,
			"github.workflow":           claims.Workflow,
			"github.environment":        claims.Environment,
			"github.runner_environment": claims.RunnerEnvironment,
			"github.actor":              claims.Actor,
		},
		ExpiresAt:   expiresAt,
		RawIdentity: ev.OIDCToken,
	}, nil
}

func (a *GitHubOIDCAttestor) validateRepository(repo string) error {
	if len(a.config.AllowedRepositories) == 0 {
		return nil
	}
	for _, pattern := range a.config.AllowedRepositories {
		matched, err := path.Match(pattern, repo)
		if err != nil {
			return fmt.Errorf("github_oidc: invalid repository pattern %q: %w", pattern, err)
		}
		if matched {
			return nil
		}
	}
	return fmt.Errorf("github_oidc: repository %q not in allowed list", repo)
}

func (a *GitHubOIDCAttestor) fetchJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	a.jwksMu.Lock()
	defer a.jwksMu.Unlock()

	if a.cachedJWKS != nil && time.Since(a.jwksFetched) < jwksCacheDuration {
		return a.cachedJWKS, nil
	}

	endpoint := a.config.JWKSEndpointOverride
	if endpoint == "" {
		endpoint = a.config.Issuer + "/.well-known/jwks"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	a.cachedJWKS = &jwks
	a.jwksFetched = time.Now()
	return &jwks, nil
}
