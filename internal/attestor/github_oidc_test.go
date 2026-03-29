package attestor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func newTestKey(t *testing.T) (*ecdsa.PrivateKey, jose.JSONWebKeySet) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     "test-key-1",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	return key, jwks
}

func signJWT(t *testing.T, key *ecdsa.PrivateKey, claims interface{}) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), "test-key-1"),
	)
	require.NoError(t, err)

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func makeGitHubEvidence(t *testing.T, token string) []byte {
	t.Helper()
	ev := map[string]string{"oidc_token": token}
	data, err := json.Marshal(ev)
	require.NoError(t, err)
	return data
}

func setupGitHubJWKSServer(t *testing.T, jwks jose.JSONWebKeySet) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestGitHubOIDCAttestor_Valid(t *testing.T) {
	key, jwks := newTestKey(t)
	srv := setupGitHubJWKSServer(t, jwks)

	now := time.Now()
	token := signJWT(t, key, map[string]interface{}{
		"iss":                srv.URL,
		"sub":                "repo:myorg/myrepo:ref:refs/heads/main",
		"aud":                "https://svidmint.example.com",
		"exp":                now.Add(10 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"nbf":                now.Add(-1 * time.Minute).Unix(),
		"repository":         "myorg/myrepo",
		"repository_owner":   "myorg",
		"sha":                "abc123def456",
		"ref":                "refs/heads/main",
		"workflow":           "ci.yml",
		"environment":        "production",
		"runner_environment": "github-hosted",
		"actor":              "octocat",
	})

	a := NewGitHubOIDCAttestor(GitHubOIDCAttestorConfig{
		AllowedRepositories:  []string{"myorg/*"},
		Issuer:               srv.URL,
		JWKSEndpointOverride: srv.URL + "/.well-known/jwks",
	})

	result, err := a.Attest(context.Background(), makeGitHubEvidence(t, token))
	require.NoError(t, err)
	assert.Equal(t, "myorg/myrepo", result.Claims["github.repository"])
	assert.Equal(t, "myorg", result.Claims["github.repository_owner"])
	assert.Equal(t, "abc123def456", result.Claims["github.sha"])
	assert.Equal(t, "refs/heads/main", result.Claims["github.ref"])
	assert.Equal(t, "ci.yml", result.Claims["github.workflow"])
	assert.Equal(t, "production", result.Claims["github.environment"])
	assert.Equal(t, "github-hosted", result.Claims["github.runner_environment"])
	assert.Equal(t, "octocat", result.Claims["github.actor"])
	assert.False(t, result.ExpiresAt.IsZero())
}

func TestGitHubOIDCAttestor_DisallowedRepo(t *testing.T) {
	key, jwks := newTestKey(t)
	srv := setupGitHubJWKSServer(t, jwks)

	now := time.Now()
	token := signJWT(t, key, map[string]interface{}{
		"iss":              srv.URL,
		"sub":              "repo:evilorg/badrepo:ref:refs/heads/main",
		"aud":              "https://svidmint.example.com",
		"exp":              now.Add(10 * time.Minute).Unix(),
		"iat":              now.Unix(),
		"nbf":              now.Add(-1 * time.Minute).Unix(),
		"repository":       "evilorg/badrepo",
		"repository_owner": "evilorg",
		"sha":              "abc123",
		"ref":              "refs/heads/main",
		"workflow":         "ci.yml",
		"actor":            "badactor",
	})

	a := NewGitHubOIDCAttestor(GitHubOIDCAttestorConfig{
		AllowedRepositories:  []string{"myorg/*"},
		Issuer:               srv.URL,
		JWKSEndpointOverride: srv.URL + "/.well-known/jwks",
	})

	_, err := a.Attest(context.Background(), makeGitHubEvidence(t, token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repository")
}

func TestGitHubOIDCAttestor_Expired(t *testing.T) {
	key, jwks := newTestKey(t)
	srv := setupGitHubJWKSServer(t, jwks)

	past := time.Now().Add(-20 * time.Minute)
	token := signJWT(t, key, map[string]interface{}{
		"iss":              srv.URL,
		"sub":              "repo:myorg/myrepo:ref:refs/heads/main",
		"aud":              "https://svidmint.example.com",
		"exp":              past.Add(5 * time.Minute).Unix(),
		"iat":              past.Unix(),
		"nbf":              past.Unix(),
		"repository":       "myorg/myrepo",
		"repository_owner": "myorg",
		"sha":              "abc123",
		"ref":              "refs/heads/main",
		"workflow":         "ci.yml",
		"actor":            "octocat",
	})

	a := NewGitHubOIDCAttestor(GitHubOIDCAttestorConfig{
		AllowedRepositories:  []string{"myorg/*"},
		Issuer:               srv.URL,
		JWKSEndpointOverride: srv.URL + "/.well-known/jwks",
	})

	_, err := a.Attest(context.Background(), makeGitHubEvidence(t, token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exp")
}

func TestGitHubOIDCAttestor_WrongIssuer(t *testing.T) {
	key, jwks := newTestKey(t)
	srv := setupGitHubJWKSServer(t, jwks)

	now := time.Now()
	token := signJWT(t, key, map[string]interface{}{
		"iss":              "https://evil-issuer.example.com",
		"sub":              "repo:myorg/myrepo:ref:refs/heads/main",
		"aud":              "https://svidmint.example.com",
		"exp":              now.Add(10 * time.Minute).Unix(),
		"iat":              now.Unix(),
		"nbf":              now.Add(-1 * time.Minute).Unix(),
		"repository":       "myorg/myrepo",
		"repository_owner": "myorg",
		"sha":              "abc123",
		"ref":              "refs/heads/main",
		"workflow":         "ci.yml",
		"actor":            "octocat",
	})

	a := NewGitHubOIDCAttestor(GitHubOIDCAttestorConfig{
		AllowedRepositories:  []string{"myorg/*"},
		Issuer:               srv.URL,
		JWKSEndpointOverride: srv.URL + "/.well-known/jwks",
	})

	_, err := a.Attest(context.Background(), makeGitHubEvidence(t, token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestGitHubOIDCAttestor_NameAndCanAttest(t *testing.T) {
	a := NewGitHubOIDCAttestor(GitHubOIDCAttestorConfig{})
	assert.Equal(t, "github_oidc", a.Name())
	assert.True(t, a.CanAttest("github_oidc"))
	assert.False(t, a.CanAttest("aws_sts"))
}
