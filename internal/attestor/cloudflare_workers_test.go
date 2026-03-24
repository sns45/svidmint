package attestor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cfGenerateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func cfSignTestJWT(t *testing.T, key *ecdsa.PrivateKey, keyID string, claims map[string]interface{}) string {
	t.Helper()
	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT")
	if keyID != "" {
		signerOpts.WithHeader(jose.HeaderKey("kid"), keyID)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &signerOpts)
	require.NoError(t, err)

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func cfJWKSHandler(t *testing.T, key *ecdsa.PrivateKey, keyID string) http.Handler {
	t.Helper()
	jwk := jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     keyID,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})
}

func TestCloudflareWorkersAttestor_Name(t *testing.T) {
	a := NewCloudflareWorkersAttestor(CloudflareWorkersAttestorConfig{})
	assert.Equal(t, "cloudflare_workers", a.Name())
}

func TestCloudflareWorkersAttestor_CanAttest(t *testing.T) {
	a := NewCloudflareWorkersAttestor(CloudflareWorkersAttestorConfig{})
	assert.True(t, a.CanAttest("cloudflare_workers"))
	assert.False(t, a.CanAttest("aws_lambda"))
	assert.False(t, a.CanAttest(""))
}

func TestCloudflareWorkersAttestor_ValidJWT(t *testing.T) {
	key := cfGenerateTestKey(t)
	keyID := "test-key-1"
	teamName := "myteam"

	srv := httptest.NewServer(cfJWKSHandler(t, key, keyID))
	defer srv.Close()

	claims := map[string]interface{}{
		"iss":   fmt.Sprintf("https://%s.cloudflareaccess.com", teamName),
		"aud":   []string{"app-audience-tag"},
		"email": "user@example.com",
		"sub":   "user-id-123",
		"iat":   time.Now().Add(-1 * time.Minute).Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"type":  "app",
	}
	token := cfSignTestJWT(t, key, keyID, claims)

	evidence, err := json.Marshal(map[string]string{"access_jwt": token})
	require.NoError(t, err)

	a := NewCloudflareWorkersAttestor(CloudflareWorkersAttestorConfig{
		Teams: []CloudflareTeamConfig{
			{Name: teamName, CertsURL: srv.URL},
		},
	})

	result, err := a.Attest(context.Background(), evidence)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, teamName, result.Claims["cf.team"])
	assert.Equal(t, "app-audience-tag", result.Claims["cf.audience"])
	assert.Equal(t, "user@example.com", result.Claims["cf.email"])
	assert.False(t, result.ExpiresAt.IsZero())
}

func TestCloudflareWorkersAttestor_ExpiredJWT(t *testing.T) {
	key := cfGenerateTestKey(t)
	keyID := "test-key-2"
	teamName := "myteam"

	srv := httptest.NewServer(cfJWKSHandler(t, key, keyID))
	defer srv.Close()

	claims := map[string]interface{}{
		"iss":   fmt.Sprintf("https://%s.cloudflareaccess.com", teamName),
		"aud":   []string{"app-audience-tag"},
		"email": "user@example.com",
		"sub":   "user-id-123",
		"iat":   time.Now().Add(-10 * time.Minute).Unix(),
		"exp":   time.Now().Add(-5 * time.Minute).Unix(),
		"type":  "app",
	}
	token := cfSignTestJWT(t, key, keyID, claims)

	evidence, err := json.Marshal(map[string]string{"access_jwt": token})
	require.NoError(t, err)

	a := NewCloudflareWorkersAttestor(CloudflareWorkersAttestorConfig{
		Teams: []CloudflareTeamConfig{
			{Name: teamName, CertsURL: srv.URL},
		},
	})

	result, err := a.Attest(context.Background(), evidence)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "exp")
}

func TestCloudflareWorkersAttestor_InvalidSignature(t *testing.T) {
	correctKey := cfGenerateTestKey(t)
	wrongKey := cfGenerateTestKey(t)
	keyID := "test-key-3"
	teamName := "myteam"

	// Server returns the correct key's public key
	srv := httptest.NewServer(cfJWKSHandler(t, correctKey, keyID))
	defer srv.Close()

	// JWT signed with the wrong key
	claims := map[string]interface{}{
		"iss":   fmt.Sprintf("https://%s.cloudflareaccess.com", teamName),
		"aud":   []string{"app-audience-tag"},
		"email": "user@example.com",
		"sub":   "user-id-123",
		"iat":   time.Now().Add(-1 * time.Minute).Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"type":  "app",
	}
	token := cfSignTestJWT(t, wrongKey, keyID, claims)

	evidence, err := json.Marshal(map[string]string{"access_jwt": token})
	require.NoError(t, err)

	a := NewCloudflareWorkersAttestor(CloudflareWorkersAttestorConfig{
		Teams: []CloudflareTeamConfig{
			{Name: teamName, CertsURL: srv.URL},
		},
	})

	result, err := a.Attest(context.Background(), evidence)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestCloudflareWorkersAttestor_WrongTeam(t *testing.T) {
	key := cfGenerateTestKey(t)
	keyID := "test-key-4"

	srv := httptest.NewServer(cfJWKSHandler(t, key, keyID))
	defer srv.Close()

	// JWT issued by "otherteam" but attestor only accepts "myteam"
	claims := map[string]interface{}{
		"iss":   "https://otherteam.cloudflareaccess.com",
		"aud":   []string{"app-audience-tag"},
		"email": "user@example.com",
		"sub":   "user-id-123",
		"iat":   time.Now().Add(-1 * time.Minute).Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"type":  "app",
	}
	token := cfSignTestJWT(t, key, keyID, claims)

	evidence, err := json.Marshal(map[string]string{"access_jwt": token})
	require.NoError(t, err)

	a := NewCloudflareWorkersAttestor(CloudflareWorkersAttestorConfig{
		Teams: []CloudflareTeamConfig{
			{Name: "myteam", CertsURL: srv.URL},
		},
	})

	result, err := a.Attest(context.Background(), evidence)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "team")
}
