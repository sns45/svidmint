package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockClientAttestor struct{}

func (m *mockClientAttestor) EvidenceType() string { return "test" }
func (m *mockClientAttestor) GatherEvidence(_ context.Context) ([]byte, error) {
	return []byte("test-evidence"), nil
}

func TestNew_RequiresServerURL(t *testing.T) {
	_, err := New(WithAttestor(&mockClientAttestor{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server URL required")
}

func TestNew_RequiresAttestor(t *testing.T) {
	_, err := New(WithServerURL("http://localhost"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attestor required")
}

func TestNew_Success(t *testing.T) {
	c, err := New(WithServerURL("http://localhost"), WithAttestor(&mockClientAttestor{}))
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestClient_AttestX509(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/attest", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req attestRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "test", req.EvidenceType)
		assert.Equal(t, "x509", req.SVIDType)

		json.NewEncoder(w).Encode(X509SVIDResponse{
			SpiffeID: "spiffe://example.org/test",
			SVID: X509SVIDData{
				CertChain: []string{"base64cert"},
				ExpiresAt: time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	client, err := New(WithServerURL(srv.URL), WithAttestor(&mockClientAttestor{}))
	require.NoError(t, err)

	resp, err := client.AttestX509(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/test", resp.SpiffeID)
	assert.Len(t, resp.SVID.CertChain, 1)
}

func TestClient_AttestJWT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/attest", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var req attestRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "jwt", req.SVIDType)
		assert.Equal(t, []string{"aud1"}, req.Audience)

		json.NewEncoder(w).Encode(JWTSVIDResponse{
			SpiffeID: "spiffe://example.org/test",
			SVID: JWTSVIDData{
				Token:     "jwt-token",
				ExpiresAt: time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	client, err := New(WithServerURL(srv.URL), WithAttestor(&mockClientAttestor{}))
	require.NoError(t, err)

	resp, err := client.AttestJWT(context.Background(), []string{"aud1"})
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/test", resp.SpiffeID)
	assert.Equal(t, "jwt-token", resp.SVID.Token)
}

func TestClient_GetBundle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/bundle", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		json.NewEncoder(w).Encode(BundleResponse{
			TrustDomain:    "example.org",
			SequenceNumber: 1,
			RefreshHint:    300,
		})
	}))
	defer srv.Close()

	client, err := New(WithServerURL(srv.URL), WithAttestor(&mockClientAttestor{}))
	require.NoError(t, err)

	resp, err := client.GetBundle(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "example.org", resp.TrustDomain)
	assert.Equal(t, int64(1), resp.SequenceNumber)
}

func TestClient_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	client, err := New(WithServerURL(srv.URL), WithAttestor(&mockClientAttestor{}))
	require.NoError(t, err)

	_, err = client.AttestX509(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestClient_WithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	c, err := New(
		WithServerURL("http://localhost"),
		WithAttestor(&mockClientAttestor{}),
		WithHTTPClient(customClient),
	)
	require.NoError(t, err)
	assert.Equal(t, customClient, c.httpClient)
}
