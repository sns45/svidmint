package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sns45/svidmint/internal/ca"
)

func generateSelfSignedCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert, key
}

func TestBundleEndpoint_ReturnsExpectedJSON(t *testing.T) {
	cert, key := generateSelfSignedCert(t)
	mock := &mockCA{
		bundle: &ca.TrustBundle{
			TrustDomain:     "example.org",
			X509Authorities: []*x509.Certificate{cert},
			JWTAuthorities: []ca.JWTAuthority{
				{KeyID: "key1", PublicKey: &key.PublicKey},
			},
			SequenceNumber: 42,
		},
	}

	srv := newTestServerWithMocks(t, mock, &mockStore{})
	req := httptest.NewRequest("GET", "/v1/bundle", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp bundleResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, "example.org", resp.TrustDomain)
	assert.Equal(t, 300, resp.RefreshHint)
	assert.Equal(t, int64(42), resp.SequenceNumber)
	assert.Len(t, resp.X509Authorities, 1)
	assert.NotEmpty(t, resp.X509Authorities[0].ASN1)
	assert.Len(t, resp.JWTAuthorities, 1)
	assert.Equal(t, "key1", resp.JWTAuthorities[0].KeyID)
	assert.Equal(t, "EC", resp.JWTAuthorities[0].PublicKey["kty"])
	assert.Equal(t, "P-256", resp.JWTAuthorities[0].PublicKey["crv"])
}

func TestBundleEndpoint_CAError(t *testing.T) {
	mock := &mockCA{
		bundleErr: assert.AnError,
	}

	srv := newTestServerWithMocks(t, mock, &mockStore{})
	req := httptest.NewRequest("GET", "/v1/bundle", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBundleEndpoint_MethodNotAllowed(t *testing.T) {
	mock := &mockCA{bundle: &ca.TrustBundle{}}
	srv := newTestServerWithMocks(t, mock, &mockStore{})
	req := httptest.NewRequest("POST", "/v1/bundle", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}
