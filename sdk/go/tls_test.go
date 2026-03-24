package sdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertAndKey creates a self signed cert and key in PEM format for testing.
func generateTestCertAndKey(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certPEM), string(keyPEM)
}

func TestTLSClientConfig(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t)

	resp := &X509SVIDResponse{
		SpiffeID: "spiffe://example.org/test",
		SVID: X509SVIDData{
			CertChain:  []string{certPEM},
			PrivateKey: keyPEM,
			ExpiresAt:  time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	}

	cfg, err := resp.TLSClientConfig()
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Len(t, cfg.Certificates, 1)
	assert.Equal(t, tls.NoClientCert, cfg.ClientAuth)
}

func TestTLSServerConfig(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey(t)

	resp := &X509SVIDResponse{
		SpiffeID: "spiffe://example.org/test",
		SVID: X509SVIDData{
			CertChain:  []string{certPEM},
			PrivateKey: keyPEM,
			ExpiresAt:  time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	}

	cfg, err := resp.TLSServerConfig()
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Len(t, cfg.Certificates, 1)
	assert.Equal(t, tls.RequireAnyClientCert, cfg.ClientAuth)
}

func TestTLSConfig_InvalidCert(t *testing.T) {
	resp := &X509SVIDResponse{
		SpiffeID: "spiffe://example.org/test",
		SVID: X509SVIDData{
			CertChain:  []string{"not-valid-pem"},
			PrivateKey: "not-valid-pem",
			ExpiresAt:  time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	}

	_, err := resp.TLSClientConfig()
	require.Error(t, err)
}

func TestTLSConfig_EmptyCertChain(t *testing.T) {
	resp := &X509SVIDResponse{
		SpiffeID: "spiffe://example.org/test",
		SVID: X509SVIDData{
			CertChain:  []string{},
			PrivateKey: "",
			ExpiresAt:  time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		},
	}

	_, err := resp.TLSClientConfig()
	require.Error(t, err)
}
