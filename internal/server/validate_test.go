package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateJWT_Valid(t *testing.T) {
	mock := &mockCA{
		validateJ: "spiffe://example.org/workload",
	}
	srv := newTestServerWithMocks(t, mock, &mockStore{})

	body, _ := json.Marshal(validateRequest{SVIDType: "jwt", SVID: "eyJhbGciOiJFUzI1NiJ9.test.sig"})
	req := httptest.NewRequest("POST", "/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp validateResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.True(t, resp.Valid)
	assert.Equal(t, "spiffe://example.org/workload", resp.SpiffeID)
}

func TestValidateJWT_Invalid(t *testing.T) {
	mock := &mockCA{
		validateJE: errors.New("token expired"),
	}
	srv := newTestServerWithMocks(t, mock, &mockStore{})

	body, _ := json.Marshal(validateRequest{SVIDType: "jwt", SVID: "bad.token.here"})
	req := httptest.NewRequest("POST", "/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp validateResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.False(t, resp.Valid)
	assert.Equal(t, "token expired", resp.Error)
}

func TestValidateX509_Valid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	mock := &mockCA{
		validateX: "spiffe://example.org/x509workload",
	}
	srv := newTestServerWithMocks(t, mock, &mockStore{})

	body, _ := json.Marshal(validateRequest{SVIDType: "x509", SVID: string(pemBlock)})
	req := httptest.NewRequest("POST", "/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp validateResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.True(t, resp.Valid)
	assert.Equal(t, "spiffe://example.org/x509workload", resp.SpiffeID)
	assert.NotZero(t, resp.ExpiresAt)
}

func TestValidateX509_Invalid(t *testing.T) {
	mock := &mockCA{
		validateXE: errors.New("certificate chain untrusted"),
	}
	srv := newTestServerWithMocks(t, mock, &mockStore{})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bad"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	body, _ := json.Marshal(validateRequest{SVIDType: "x509", SVID: string(pemBlock)})
	req := httptest.NewRequest("POST", "/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp validateResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.False(t, resp.Valid)
	assert.Contains(t, resp.Error, "untrusted")
}

func TestValidate_BadSVIDType(t *testing.T) {
	mock := &mockCA{}
	srv := newTestServerWithMocks(t, mock, &mockStore{})

	body, _ := json.Marshal(validateRequest{SVIDType: "unknown", SVID: "data"})
	req := httptest.NewRequest("POST", "/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidate_MalformedBody(t *testing.T) {
	mock := &mockCA{}
	srv := newTestServerWithMocks(t, mock, &mockStore{})

	req := httptest.NewRequest("POST", "/v1/validate", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
