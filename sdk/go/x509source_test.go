package sdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface checks: X509Source must satisfy go-spiffe/v2 interfaces.
var _ x509svid.Source = (*X509Source)(nil)
var _ x509bundle.Source = (*X509Source)(nil)

// testCA generates a self-signed CA certificate and an SVID leaf certificate
// signed by that CA, both using ECDSA P-256 as required by the SPIFFE spec.
func testCA(t *testing.T, spiffeID string) (caCertPEM, leafCertPEM, leafKeyPEM []byte) {
	t.Helper()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	// Generate leaf key
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, err := url.Parse(spiffeID)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(5 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{spiffeURI},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	leafCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertDER})

	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)
	leafKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})

	return caCertPEM, leafCertPEM, leafKeyPEM
}

// newMockSvidmintServer creates an httptest server that responds to /v1/attest
// with a valid X.509 SVID and to /v1/bundle with a trust bundle.
func newMockSvidmintServer(t *testing.T, spiffeID string, caCertPEM, leafCertPEM, leafKeyPEM []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/attest":
			json.NewEncoder(w).Encode(X509SVIDResponse{
				SpiffeID: spiffeID,
				SVID: X509SVIDData{
					CertChain:  []string{string(leafCertPEM), string(caCertPEM)},
					PrivateKey: string(leafKeyPEM),
					ExpiresAt:  time.Now().Add(5 * time.Minute).Format(time.RFC3339),
				},
			})
		case "/v1/bundle":
			td, _ := spiffeid.TrustDomainFromString("example.org")
			_ = td
			json.NewEncoder(w).Encode(BundleResponse{
				TrustDomain:     "example.org",
				X509Authorities: []string{string(caCertPEM)},
				SequenceNumber:  1,
				RefreshHint:     300,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestX509Source_ImplementsGoSpiffeInterfaces(t *testing.T) {
	// The compile-time checks above are the real test. This test simply
	// confirms the type assertions succeed at runtime as well.
	var svidSource x509svid.Source = &X509Source{}
	var bundleSource x509bundle.Source = &X509Source{}
	assert.NotNil(t, svidSource)
	assert.NotNil(t, bundleSource)
}

func TestX509Source_GetX509SVID(t *testing.T) {
	spiffeID := "spiffe://example.org/workload"
	caCertPEM, leafCertPEM, leafKeyPEM := testCA(t, spiffeID)
	srv := newMockSvidmintServer(t, spiffeID, caCertPEM, leafCertPEM, leafKeyPEM)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	source, err := NewX509Source(ctx,
		WithServerURL(srv.URL),
		WithAttestor(&mockClientAttestor{}),
	)
	require.NoError(t, err)
	defer source.Close()

	svid, err := source.GetX509SVID()
	require.NoError(t, err)
	require.NotNil(t, svid)

	// The SVID must contain the correct SPIFFE ID
	assert.Equal(t, spiffeID, svid.ID.String())

	// Must have at least one certificate
	require.NotEmpty(t, svid.Certificates)

	// The leaf cert must have the SPIFFE ID as a URI SAN
	require.Len(t, svid.Certificates[0].URIs, 1)
	assert.Equal(t, spiffeID, svid.Certificates[0].URIs[0].String())

	// Must have a private key
	assert.NotNil(t, svid.PrivateKey)
}

func TestX509Source_GetX509BundleForTrustDomain(t *testing.T) {
	spiffeID := "spiffe://example.org/workload"
	caCertPEM, leafCertPEM, leafKeyPEM := testCA(t, spiffeID)
	srv := newMockSvidmintServer(t, spiffeID, caCertPEM, leafCertPEM, leafKeyPEM)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	source, err := NewX509Source(ctx,
		WithServerURL(srv.URL),
		WithAttestor(&mockClientAttestor{}),
	)
	require.NoError(t, err)
	defer source.Close()

	td, err := spiffeid.TrustDomainFromString("example.org")
	require.NoError(t, err)

	bundle, err := source.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.NotNil(t, bundle)

	// Bundle must contain at least one X.509 authority
	assert.NotEmpty(t, bundle.X509Authorities(), "bundle should contain X.509 authorities")
}

func TestX509Source_Close(t *testing.T) {
	spiffeID := "spiffe://example.org/workload"
	caCertPEM, leafCertPEM, leafKeyPEM := testCA(t, spiffeID)
	srv := newMockSvidmintServer(t, spiffeID, caCertPEM, leafCertPEM, leafKeyPEM)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	source, err := NewX509Source(ctx,
		WithServerURL(srv.URL),
		WithAttestor(&mockClientAttestor{}),
	)
	require.NoError(t, err)

	err = source.Close()
	require.NoError(t, err)

	// After close, GetX509SVID should return an error
	_, err = source.GetX509SVID()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestX509Source_NilSVID_ReturnsError(t *testing.T) {
	s := &X509Source{}
	_, err := s.GetX509SVID()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no SVID available")
}

func TestX509Source_NilBundle_ReturnsError(t *testing.T) {
	s := &X509Source{}
	td, _ := spiffeid.TrustDomainFromString("example.org")
	_, err := s.GetX509BundleForTrustDomain(td)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no bundle available")
}
