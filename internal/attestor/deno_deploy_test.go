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

func denoGenerateTestKey(t *testing.T) (*ecdsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     "test-key-1",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	return key, jwk
}

func denoSignTestJWT(t *testing.T, key *ecdsa.PrivateKey, claims interface{}) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), "test-key-1"),
	)
	require.NoError(t, err)

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func denoSetupJWKSServer(t *testing.T, jwk jose.JSONWebKey) *httptest.Server {
	t.Helper()
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	jwksBytes, err := json.Marshal(jwks)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDenoDeployAttestor_Valid(t *testing.T) {
	key, jwk := denoGenerateTestKey(t)
	jwksSrv := denoSetupJWKSServer(t, jwk)

	claims := denoClaims{
		Issuer:      "https://oidc.deno.com",
		Subject:     "deno-deploy:project-abc",
		Expiry:      jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:    jwt.NewNumericDate(time.Now()),
		DenoProject: "my-deno-project",
		Repository:  "org/my-repo",
	}

	token := denoSignTestJWT(t, key, claims)
	evidence, err := json.Marshal(denoOIDCEvidence{Token: token})
	require.NoError(t, err)

	attestor := NewDenoDeployAttestor(DenoDeployAttestorConfig{
		AllowedIssuers:  []string{"https://oidc.deno.com"},
		JWKSURLOverride: jwksSrv.URL,
	})

	result, err := attestor.Attest(context.Background(), evidence)
	require.NoError(t, err)
	assert.Equal(t, "https://oidc.deno.com", result.Claims["iss"])
	assert.Equal(t, "deno-deploy:project-abc", result.Claims["sub"])
	assert.Equal(t, "my-deno-project", result.Claims["deno.project"])
	assert.Equal(t, "org/my-repo", result.Claims["repository"])
	assert.Equal(t, "deno-deploy:project-abc", result.RawIdentity)
	assert.False(t, result.ExpiresAt.IsZero())
}

func TestDenoDeployAttestor_ExpiredToken(t *testing.T) {
	key, jwk := denoGenerateTestKey(t)
	jwksSrv := denoSetupJWKSServer(t, jwk)

	claims := denoClaims{
		Issuer:   "https://oidc.deno.com",
		Subject:  "deno-deploy:expired",
		Expiry:   jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
	}

	token := denoSignTestJWT(t, key, claims)
	evidence, err := json.Marshal(denoOIDCEvidence{Token: token})
	require.NoError(t, err)

	attestor := NewDenoDeployAttestor(DenoDeployAttestorConfig{
		JWKSURLOverride: jwksSrv.URL,
	})

	_, err = attestor.Attest(context.Background(), evidence)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestDenoDeployAttestor_UntrustedIssuer(t *testing.T) {
	key, _ := denoGenerateTestKey(t)

	claims := denoClaims{
		Issuer:   "https://evil.example.com",
		Subject:  "evil-subject",
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	token := denoSignTestJWT(t, key, claims)
	evidence, err := json.Marshal(denoOIDCEvidence{Token: token})
	require.NoError(t, err)

	attestor := NewDenoDeployAttestor(DenoDeployAttestorConfig{
		AllowedIssuers: []string{"https://oidc.deno.com"},
	})

	_, err = attestor.Attest(context.Background(), evidence)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "untrusted issuer")
}

func TestDenoDeployAttestor_InvalidEvidence(t *testing.T) {
	attestor := NewDenoDeployAttestor(DenoDeployAttestorConfig{})

	_, err := attestor.Attest(context.Background(), []byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid evidence")
}

func TestDenoDeployAttestor_MissingToken(t *testing.T) {
	attestor := NewDenoDeployAttestor(DenoDeployAttestorConfig{})

	evidence, _ := json.Marshal(denoOIDCEvidence{Token: ""})
	_, err := attestor.Attest(context.Background(), evidence)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing token")
}

func TestDenoDeployAttestor_InvalidSignature(t *testing.T) {
	signingKey, _ := denoGenerateTestKey(t)
	_, wrongJWK := denoGenerateTestKey(t) // different key for JWKS
	jwksSrv := denoSetupJWKSServer(t, wrongJWK)

	claims := denoClaims{
		Issuer:   "https://oidc.deno.com",
		Subject:  "deno-deploy:bad-sig",
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	token := denoSignTestJWT(t, signingKey, claims)
	evidence, err := json.Marshal(denoOIDCEvidence{Token: token})
	require.NoError(t, err)

	attestor := NewDenoDeployAttestor(DenoDeployAttestorConfig{
		JWKSURLOverride: jwksSrv.URL,
	})

	_, err = attestor.Attest(context.Background(), evidence)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestDenoDeployAttestor_JWKSFetchError(t *testing.T) {
	key, _ := denoGenerateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	claims := denoClaims{
		Issuer:   "https://oidc.deno.com",
		Subject:  "deno-deploy:jwks-fail",
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	token := denoSignTestJWT(t, key, claims)
	evidence, err := json.Marshal(denoOIDCEvidence{Token: token})
	require.NoError(t, err)

	attestor := NewDenoDeployAttestor(DenoDeployAttestorConfig{
		JWKSURLOverride: srv.URL,
	})

	_, err = attestor.Attest(context.Background(), evidence)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWKS")
}

func TestDenoDeployAttestor_NameAndCanAttest(t *testing.T) {
	a := NewDenoDeployAttestor(DenoDeployAttestorConfig{})
	assert.Equal(t, "deno_oidc", a.Name())
	assert.True(t, a.CanAttest("deno_oidc"))
	assert.False(t, a.CanAttest("aws_sts"))
	assert.False(t, a.CanAttest("github_oidc"))
}

func TestDenoDeployAttestor_WithoutOptionalClaims(t *testing.T) {
	key, jwk := denoGenerateTestKey(t)
	jwksSrv := denoSetupJWKSServer(t, jwk)

	claims := denoClaims{
		Issuer:   "https://oidc.deno.com",
		Subject:  "deno-deploy:minimal",
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	token := denoSignTestJWT(t, key, claims)
	evidence, err := json.Marshal(denoOIDCEvidence{Token: token})
	require.NoError(t, err)

	attestor := NewDenoDeployAttestor(DenoDeployAttestorConfig{
		JWKSURLOverride: jwksSrv.URL,
	})

	result, err := attestor.Attest(context.Background(), evidence)
	require.NoError(t, err)
	assert.Equal(t, "deno-deploy:minimal", result.Claims["sub"])
	_, hasDeno := result.Claims["deno.project"]
	assert.False(t, hasDeno)
	_, hasRepo := result.Claims["repository"]
	assert.False(t, hasRepo)
}
