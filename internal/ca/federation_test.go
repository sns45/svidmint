package ca

import (
	"context"
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

	"github.com/sns45/svidmint/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spiffeBundleResponse models the SPIFFE trust bundle JSON format
// returned by a federation endpoint.
type spiffeBundleResponse struct {
	Keys []spiffeBundleKey `json:"keys"`
}

type spiffeBundleKey struct {
	Kty  string   `json:"kty"`
	Crv  string   `json:"crv"`
	X    string   `json:"x"`
	Y    string   `json:"y"`
	Use  string   `json:"use"`
	X5C  [][]byte `json:"x5c,omitempty"`
	Kid  string   `json:"kid,omitempty"`
}

func generateSelfSignedCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func serveSPIFFEBundle(t *testing.T, cert *x509.Certificate) *httptest.Server {
	t.Helper()
	bundle := spiffeBundleResponse{
		Keys: []spiffeBundleKey{
			{
				Kty: "EC",
				Crv: "P-256",
				Use: "x509-svid",
				X5C: [][]byte{cert.Raw},
			},
		},
	}
	data, err := json.Marshal(bundle)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNewBundleFetcher(t *testing.T) {
	configs := []config.FederationBundleConfig{
		{
			TrustDomain:     "domain-a.example",
			Endpoint:        "https://domain-a.example/bundle",
			Type:            "https_web",
			RefreshInterval: "5m",
		},
	}

	fetcher := NewBundleFetcher(configs)
	require.NotNil(t, fetcher)
	assert.Len(t, fetcher.configs, 1)
	assert.NotNil(t, fetcher.bundles)
	assert.NotNil(t, fetcher.httpClient)
}

func TestFetch_SingleDomain(t *testing.T) {
	cert, _ := generateSelfSignedCert(t)
	srv := serveSPIFFEBundle(t, cert)

	configs := []config.FederationBundleConfig{
		{
			TrustDomain:     "remote.example",
			Endpoint:        srv.URL,
			Type:            "https_web",
			RefreshInterval: "1m",
		},
	}

	fetcher := NewBundleFetcher(configs)
	bundles, err := fetcher.Fetch(context.Background())
	require.NoError(t, err)
	require.Contains(t, bundles, "remote.example")

	b := bundles["remote.example"]
	assert.Equal(t, "remote.example", b.TrustDomain)
	require.Len(t, b.X509Authorities, 1)
	assert.Equal(t, cert.Raw, b.X509Authorities[0].Raw)
}

func TestFetch_MultipleDomains(t *testing.T) {
	cert1, _ := generateSelfSignedCert(t)
	cert2, _ := generateSelfSignedCert(t)
	srv1 := serveSPIFFEBundle(t, cert1)
	srv2 := serveSPIFFEBundle(t, cert2)

	configs := []config.FederationBundleConfig{
		{TrustDomain: "alpha.example", Endpoint: srv1.URL, Type: "https_web", RefreshInterval: "1m"},
		{TrustDomain: "beta.example", Endpoint: srv2.URL, Type: "https_web", RefreshInterval: "1m"},
	}

	fetcher := NewBundleFetcher(configs)
	bundles, err := fetcher.Fetch(context.Background())
	require.NoError(t, err)
	assert.Len(t, bundles, 2)
	assert.Contains(t, bundles, "alpha.example")
	assert.Contains(t, bundles, "beta.example")
}

func TestFetch_InvalidEndpoint(t *testing.T) {
	configs := []config.FederationBundleConfig{
		{TrustDomain: "bad.example", Endpoint: "http://127.0.0.1:1", Type: "https_web", RefreshInterval: "1m"},
	}

	fetcher := NewBundleFetcher(configs)
	_, err := fetcher.Fetch(context.Background())
	assert.Error(t, err)
}

func TestFetch_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)

	configs := []config.FederationBundleConfig{
		{TrustDomain: "bad.example", Endpoint: srv.URL, Type: "https_web", RefreshInterval: "1m"},
	}

	fetcher := NewBundleFetcher(configs)
	_, err := fetcher.Fetch(context.Background())
	assert.Error(t, err)
}

func TestFetch_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	configs := []config.FederationBundleConfig{
		{TrustDomain: "err.example", Endpoint: srv.URL, Type: "https_web", RefreshInterval: "1m"},
	}

	fetcher := NewBundleFetcher(configs)
	_, err := fetcher.Fetch(context.Background())
	assert.Error(t, err)
}

func TestGetBundle_Federation(t *testing.T) {
	cert, _ := generateSelfSignedCert(t)
	srv := serveSPIFFEBundle(t, cert)

	configs := []config.FederationBundleConfig{
		{TrustDomain: "domain.example", Endpoint: srv.URL, Type: "https_web", RefreshInterval: "1m"},
	}

	fetcher := NewBundleFetcher(configs)
	_, err := fetcher.Fetch(context.Background())
	require.NoError(t, err)

	b, ok := fetcher.GetBundle("domain.example")
	assert.True(t, ok)
	assert.Equal(t, "domain.example", b.TrustDomain)

	_, ok = fetcher.GetBundle("nonexistent.example")
	assert.False(t, ok)
}

func TestStart_PeriodicRefresh(t *testing.T) {
	callCount := 0
	cert, _ := generateSelfSignedCert(t)
	bundle := spiffeBundleResponse{
		Keys: []spiffeBundleKey{
			{Kty: "EC", Crv: "P-256", Use: "x509-svid", X5C: [][]byte{cert.Raw}},
		},
	}
	data, err := json.Marshal(bundle)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	configs := []config.FederationBundleConfig{
		{TrustDomain: "refresh.example", Endpoint: srv.URL, Type: "https_web", RefreshInterval: "100ms"},
	}

	fetcher := NewBundleFetcher(configs)
	ctx, cancel := context.WithCancel(context.Background())

	go fetcher.Start(ctx)

	// Allow a few refresh cycles
	time.Sleep(350 * time.Millisecond)
	cancel()

	// The fetcher should have called the endpoint multiple times
	assert.GreaterOrEqual(t, callCount, 2)

	b, ok := fetcher.GetBundle("refresh.example")
	assert.True(t, ok)
	assert.NotNil(t, b)
}

func TestStart_CancellationStopsRefresh(t *testing.T) {
	cert, _ := generateSelfSignedCert(t)
	srv := serveSPIFFEBundle(t, cert)

	configs := []config.FederationBundleConfig{
		{TrustDomain: "stop.example", Endpoint: srv.URL, Type: "https_web", RefreshInterval: "50ms"},
	}

	fetcher := NewBundleFetcher(configs)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		fetcher.Start(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Start returned after cancellation, which is expected.
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestFetch_EmptyX5C(t *testing.T) {
	// Bundle with no x5c entries should produce a bundle with zero authorities
	bundle := spiffeBundleResponse{
		Keys: []spiffeBundleKey{
			{Kty: "EC", Crv: "P-256", Use: "x509-svid"},
		},
	}
	data, err := json.Marshal(bundle)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	configs := []config.FederationBundleConfig{
		{TrustDomain: "empty.example", Endpoint: srv.URL, Type: "https_web", RefreshInterval: "1m"},
	}

	fetcher := NewBundleFetcher(configs)
	bundles, err := fetcher.Fetch(context.Background())
	require.NoError(t, err)
	assert.Empty(t, bundles["empty.example"].X509Authorities)
}
