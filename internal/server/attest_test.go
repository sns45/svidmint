package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sns45/svidmint/internal/attestor"
	"github.com/sns45/svidmint/internal/ca"
	"github.com/sns45/svidmint/internal/config"
	"github.com/sns45/svidmint/internal/entry"
)

// mockCA implements ca.CA for testing.
type mockCA struct {
	x509SVID   *ca.X509SVID
	x509Err    error
	jwtSVID    *ca.JWTSVID
	jwtErr     error
	bundle     *ca.TrustBundle
	bundleErr  error
	jwksData   []byte
	jwksErr    error
	validateX  string
	validateXE error
	validateJ  string
	validateJE error
}

func (m *mockCA) SignX509SVID(_ context.Context, _ string, _ *x509.CertificateRequest, _ int) (*ca.X509SVID, error) {
	return m.x509SVID, m.x509Err
}

func (m *mockCA) SignJWTSVID(_ context.Context, _ string, _ []string, _ int) (*ca.JWTSVID, error) {
	return m.jwtSVID, m.jwtErr
}

func (m *mockCA) GetBundle(_ context.Context) (*ca.TrustBundle, error) {
	return m.bundle, m.bundleErr
}

func (m *mockCA) ValidateX509SVID(_ context.Context, _ []*x509.Certificate) (string, error) {
	return m.validateX, m.validateXE
}

func (m *mockCA) ValidateJWTSVID(_ context.Context, _ string, _ string) (string, error) {
	return m.validateJ, m.validateJE
}

func (m *mockCA) JWKS() ([]byte, error) {
	return m.jwksData, m.jwksErr
}

// mockStore implements entry.Store for testing.
type mockStore struct {
	matchEntry *entry.RegistrationEntry
	matchErr   error
}

func (m *mockStore) Create(_ context.Context, _ *entry.RegistrationEntry) error { return nil }
func (m *mockStore) Get(_ context.Context, _ string) (*entry.RegistrationEntry, error) {
	return nil, nil
}
func (m *mockStore) List(_ context.Context) ([]*entry.RegistrationEntry, error) { return nil, nil }
func (m *mockStore) Update(_ context.Context, _ *entry.RegistrationEntry) error { return nil }
func (m *mockStore) Delete(_ context.Context, _ string) error                   { return nil }
func (m *mockStore) Match(_ context.Context, _ string, _ map[string]string) (*entry.RegistrationEntry, error) {
	return m.matchEntry, m.matchErr
}
func (m *mockStore) Close() error { return nil }

// mockAttestorForServer implements attestor.Attestor for testing.
type mockAttestorForServer struct {
	name         string
	evidenceType string
	result       *attestor.AttestationResult
	err          error
}

func (m *mockAttestorForServer) Name() string { return m.name }
func (m *mockAttestorForServer) CanAttest(et string) bool {
	return et == m.evidenceType
}
func (m *mockAttestorForServer) Attest(_ context.Context, _ []byte) (*attestor.AttestationResult, error) {
	return m.result, m.err
}

func newTestServerWithMocks(t *testing.T, caImpl ca.CA, store entry.Store, attestors ...attestor.Attestor) *Server {
	t.Helper()
	logger := zap.NewNop()
	registry := attestor.NewRegistry(attestors...)
	srv, err := New(caImpl, registry, store, &config.Config{}, logger)
	require.NoError(t, err)
	return srv
}

func makeAttestBody(t *testing.T, evidenceType, evidence, svidType string, audience []string) *bytes.Buffer {
	t.Helper()
	body := attestor.AttestRequest{
		EvidenceType: evidenceType,
		Evidence:     base64.StdEncoding.EncodeToString([]byte(evidence)),
		SVIDType:     svidType,
		Audience:     audience,
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return bytes.NewBuffer(b)
}

func TestAttest_ValidX509(t *testing.T) {
	// Create a self-signed cert to use in the mock response.
	mockCert := &x509.Certificate{Raw: []byte("mock-cert-der")}
	expiresAt := time.Now().Add(time.Hour)

	srv := newTestServerWithMocks(t,
		&mockCA{
			x509SVID: &ca.X509SVID{
				SpiffeID:  "spiffe://example.org/workload",
				CertChain: []*x509.Certificate{mockCert},
				ExpiresAt: expiresAt,
			},
		},
		&mockStore{
			matchEntry: &entry.RegistrationEntry{
				ID:       "entry-1",
				SpiffeID: "spiffe://example.org/workload",
				Attestor: "aws_sts",
				TTL:      3600,
			},
		},
		&mockAttestorForServer{
			name:         "aws_sts",
			evidenceType: "aws_sts",
			result: &attestor.AttestationResult{
				Claims:    map[string]string{"account_id": "123456789012"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
	)

	body := makeAttestBody(t, "aws_sts", "some-evidence", "x509", nil)
	req := httptest.NewRequest("POST", "/v1/attest", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp attestResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/workload", resp.SpiffeID)
	assert.Equal(t, "x509", resp.SVIDType)

	// The X.509 SVID must be under resp.SVID with cert_chain as a JSON array.
	require.NotNil(t, resp.SVID)
	assert.NotEmpty(t, resp.SVID.CertChain)
	assert.NotEmpty(t, resp.SVID.ExpiresAt)
}

func TestAttest_ValidJWT(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)

	srv := newTestServerWithMocks(t,
		&mockCA{
			jwtSVID: &ca.JWTSVID{
				SpiffeID:  "spiffe://example.org/workload",
				Token:     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.mock.token",
				ExpiresAt: expiresAt,
			},
		},
		&mockStore{
			matchEntry: &entry.RegistrationEntry{
				ID:       "entry-1",
				SpiffeID: "spiffe://example.org/workload",
				Attestor: "github_oidc",
				TTL:      1800,
			},
		},
		&mockAttestorForServer{
			name:         "github_oidc",
			evidenceType: "github_oidc",
			result: &attestor.AttestationResult{
				Claims:    map[string]string{"repository": "org/repo"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
	)

	body := makeAttestBody(t, "github_oidc", "oidc-token", "jwt", []string{"api.example.org"})
	req := httptest.NewRequest("POST", "/v1/attest", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp attestResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/workload", resp.SpiffeID)
	assert.Equal(t, "jwt", resp.SVIDType)
	assert.Equal(t, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.mock.token", resp.Token)
	assert.NotEmpty(t, resp.ExpiresAt)
}

func TestAttest_InvalidRequestBody(t *testing.T) {
	srv := newTestServerWithMocks(t, &mockCA{}, &mockStore{})

	req := httptest.NewRequest("POST", "/v1/attest", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp map[string]APIError
	err := json.NewDecoder(w.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "INVALID_REQUEST", errResp["error"].Code)
}

func TestAttest_MissingRequiredFields(t *testing.T) {
	srv := newTestServerWithMocks(t, &mockCA{}, &mockStore{})

	tests := []struct {
		name string
		body string
	}{
		{"missing evidence_type", `{"evidence":"dGVzdA==","svid_type":"x509"}`},
		{"missing evidence", `{"evidence_type":"aws_sts","svid_type":"x509"}`},
		{"missing svid_type", `{"evidence_type":"aws_sts","evidence":"dGVzdA=="}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/attest", bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var errResp map[string]APIError
			err := json.NewDecoder(w.Body).Decode(&errResp)
			require.NoError(t, err)
			assert.Equal(t, "INVALID_REQUEST", errResp["error"].Code)
		})
	}
}

func TestAttest_AttestationFailed(t *testing.T) {
	srv := newTestServerWithMocks(t,
		&mockCA{},
		&mockStore{},
		&mockAttestorForServer{
			name:         "aws_sts",
			evidenceType: "aws_sts",
			err:          errors.New("invalid credentials"),
		},
	)

	body := makeAttestBody(t, "aws_sts", "bad-evidence", "x509", nil)
	req := httptest.NewRequest("POST", "/v1/attest", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var errResp map[string]APIError
	err := json.NewDecoder(w.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "ATTESTATION_FAILED", errResp["error"].Code)
}

func TestAttest_NoMatchingEntry(t *testing.T) {
	srv := newTestServerWithMocks(t,
		&mockCA{},
		&mockStore{
			matchEntry: nil,
		},
		&mockAttestorForServer{
			name:         "aws_sts",
			evidenceType: "aws_sts",
			result: &attestor.AttestationResult{
				Claims:    map[string]string{"account_id": "123456789012"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
	)

	body := makeAttestBody(t, "aws_sts", "some-evidence", "x509", nil)
	req := httptest.NewRequest("POST", "/v1/attest", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var errResp map[string]APIError
	err := json.NewDecoder(w.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "NO_MATCHING_ENTRY", errResp["error"].Code)
}

func TestAttest_JWTMissingAudience(t *testing.T) {
	srv := newTestServerWithMocks(t, &mockCA{}, &mockStore{})

	body := map[string]interface{}{
		"evidence_type": "aws_sts",
		"evidence":      base64.StdEncoding.EncodeToString([]byte("test")),
		"svid_type":     "jwt",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/attest", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp map[string]APIError
	err := json.NewDecoder(w.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "INVALID_REQUEST", errResp["error"].Code)
}

func TestAttest_InvalidSVIDType(t *testing.T) {
	srv := newTestServerWithMocks(t, &mockCA{}, &mockStore{})

	body := map[string]interface{}{
		"evidence_type": "aws_sts",
		"evidence":      base64.StdEncoding.EncodeToString([]byte("test")),
		"svid_type":     "invalid",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/attest", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
