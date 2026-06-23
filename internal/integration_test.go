//go:build integration

package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sns45/svidmint/internal/attestor"
	"github.com/sns45/svidmint/internal/ca"
	"github.com/sns45/svidmint/internal/config"
	"github.com/sns45/svidmint/internal/entry"
	"github.com/sns45/svidmint/internal/server"
)

// testAttestorImpl is a minimal attestor for integration testing that always
// succeeds and returns fixed claims.
type testAttestorImpl struct{}

func (a *testAttestorImpl) Name() string { return "test_attestor" }

func (a *testAttestorImpl) CanAttest(evidenceType string) bool {
	return evidenceType == "test_attestor"
}

func (a *testAttestorImpl) Attest(_ context.Context, _ []byte) (*attestor.AttestationResult, error) {
	return &attestor.AttestationResult{
		Claims: map[string]string{
			"test.claim": "test-value",
		},
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		RawIdentity: "test-workload",
	}, nil
}

func TestEndToEnd_AttestAndValidate(t *testing.T) {
	dir := t.TempDir()

	// 1. Create CA
	caImpl, err := ca.NewSelfSignedCA(ca.SelfSignedCAConfig{
		TrustDomain:  "integration.test",
		KeyType:      "ec-p256",
		RootKeyPath:  filepath.Join(dir, "root.key"),
		RootCertPath: filepath.Join(dir, "root.crt"),
		SigningTTL:   "24h",
		DefaultTTL:   "5m",
		MaxTTL:       "1h",
	})
	require.NoError(t, err)

	// 2. Create SQLite store with a test registration entry
	store, err := entry.NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	err = store.Create(ctx, &entry.RegistrationEntry{
		ID:        "e2e-test",
		SpiffeID:  "spiffe://integration.test/e2e/workload",
		Attestor:  "test_attestor",
		Selectors: []string{"test.claim:test-value"},
		TTL:       300,
	})
	require.NoError(t, err)

	// 3. Create attestor registry with the test attestor
	registry := attestor.NewRegistry(&testAttestorImpl{})

	// 4. Create server
	cfg := &config.Config{TrustDomain: "integration.test"}
	logger := zap.NewNop()
	srv, err := server.New(caImpl, registry, store, cfg, logger)
	require.NoError(t, err)

	// 5. Start httptest.Server
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// 6. Issue JWT SVID via attest endpoint
	jwtResp := attestSVID(t, ts.URL, "jwt", []string{"test-audience"})
	assert.Equal(t, "spiffe://integration.test/e2e/workload", jwtResp["spiffe_id"])
	assert.Equal(t, "jwt", jwtResp["svid_type"])
	assert.NotEmpty(t, jwtResp["token"])
	assert.NotEmpty(t, jwtResp["expires_at"])

	// 7. Issue X.509 SVID via attest endpoint
	x509Resp := attestSVID(t, ts.URL, "x509", nil)
	assert.Equal(t, "spiffe://integration.test/e2e/workload", x509Resp["spiffe_id"])
	assert.Equal(t, "x509", x509Resp["svid_type"])

	// The response must carry a nested "svid" object with cert_chain as an array.
	svidObj, ok := x509Resp["svid"].(map[string]interface{})
	require.True(t, ok, "svid field must be a JSON object")
	certChain, ok := svidObj["cert_chain"].([]interface{})
	require.True(t, ok, "svid.cert_chain must be a JSON array")
	assert.NotEmpty(t, certChain, "svid.cert_chain must not be empty")
	assert.NotEmpty(t, svidObj["expires_at"])

	// 8. Validate X.509 SVID via validate endpoint using the full chain.
	validateX509(t, ts.URL, x509Resp)

	// 9. Get trust bundle
	bundleResp := getBundle(t, ts.URL)
	assert.Equal(t, "integration.test", bundleResp["trust_domain"])
	authorities, ok := bundleResp["x509_authorities"].([]interface{})
	assert.True(t, ok, "x509_authorities should be an array")
	assert.NotEmpty(t, authorities)

	// 10. Get JWKS
	jwksResp := getJWKS(t, ts.URL)
	assert.Contains(t, jwksResp, "keys")
	keys, ok := jwksResp["keys"].([]interface{})
	assert.True(t, ok, "keys should be an array")
	assert.NotEmpty(t, keys)

	// 11. Health check
	healthResp := doGet(t, ts.URL+"/v1/health")
	assert.Contains(t, healthResp, "status")
}

// attestSVID sends an attestation request and returns the parsed JSON response.
func attestSVID(t *testing.T, baseURL, svidType string, audience []string) map[string]interface{} {
	t.Helper()

	body := map[string]interface{}{
		"evidence_type": "test_attestor",
		"evidence":      base64.StdEncoding.EncodeToString([]byte("test-evidence")),
		"svid_type":     svidType,
	}
	if len(audience) > 0 {
		body["audience"] = audience
	}

	return doPost(t, baseURL+"/v1/attest", body)
}

// validateX509 sends a validate request for the X.509 SVID returned by attest.
// The attest endpoint now returns the full cert chain (leaf + intermediate) as
// a JSON array under svid.cert_chain. We concatenate all PEM strings and send
// them to the validate endpoint.
func validateX509(t *testing.T, baseURL string, attestResp map[string]interface{}) {
	t.Helper()

	svidObj, ok := attestResp["svid"].(map[string]interface{})
	require.True(t, ok, "svid field must be a JSON object")

	chainIface, ok := svidObj["cert_chain"].([]interface{})
	require.True(t, ok, "svid.cert_chain must be a JSON array")
	require.NotEmpty(t, chainIface)

	// Concatenate all PEM blocks into a single string for the validate endpoint.
	var fullChain string
	for _, c := range chainIface {
		certPEM, ok := c.(string)
		require.True(t, ok, "each element of svid.cert_chain must be a string")
		fullChain += certPEM
	}

	body := map[string]interface{}{
		"svid_type": "x509",
		"svid":      fullChain,
	}

	resp := doPost(t, baseURL+"/v1/validate", body)
	// The validate endpoint should return a well-formed response.
	_, hasValid := resp["valid"]
	assert.True(t, hasValid, "response should contain a valid field")
}

// getBundle fetches the trust bundle.
func getBundle(t *testing.T, baseURL string) map[string]interface{} {
	t.Helper()
	return doGet(t, baseURL+"/v1/bundle")
}

// getJWKS fetches the JWKS endpoint.
func getJWKS(t *testing.T, baseURL string) map[string]interface{} {
	t.Helper()
	return doGet(t, baseURL+"/v1/jwks")
}

// doPost sends a POST request with a JSON body and returns the parsed response.
func doPost(t *testing.T, url string, body map[string]interface{}) map[string]interface{} {
	t.Helper()

	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)

	resp, err := http.Post(url, "application/json", bytes.NewReader(jsonBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status %d; body: %s", resp.StatusCode, string(data))

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)
	return result
}

// doGet sends a GET request and returns the parsed JSON response.
func doGet(t *testing.T, url string) map[string]interface{} {
	t.Helper()

	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status %d; body: %s", resp.StatusCode, string(data))

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)
	return result
}
