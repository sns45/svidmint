package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCA(t *testing.T) *SelfSignedCA {
	t.Helper()
	dir := t.TempDir()
	ca, err := NewSelfSignedCA(SelfSignedCAConfig{
		TrustDomain:  "example.org",
		KeyType:      "ec-p256",
		RootKeyPath:  filepath.Join(dir, "root.key"),
		RootCertPath: filepath.Join(dir, "root.crt"),
		SigningTTL:   "24h",
		DefaultTTL:   "5m",
		MaxTTL:       "1h",
	})
	require.NoError(t, err)
	return ca
}

func TestInitGeneratesRootCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewSelfSignedCA(SelfSignedCAConfig{
		TrustDomain:  "example.org",
		KeyType:      "ec-p256",
		RootKeyPath:  filepath.Join(dir, "root.key"),
		RootCertPath: filepath.Join(dir, "root.crt"),
		SigningTTL:   "24h",
		DefaultTTL:   "5m",
		MaxTTL:       "1h",
	})
	require.NoError(t, err)

	// Root cert exists on disk
	_, err = os.Stat(filepath.Join(dir, "root.key"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, "root.crt"))
	assert.NoError(t, err)

	// Check key file permissions
	info, _ := os.Stat(filepath.Join(dir, "root.key"))
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Root cert is valid CA
	assert.True(t, ca.rootCert.IsCA)
	assert.Equal(t, "svidmint Root CA", ca.rootCert.Subject.CommonName)
	assert.Contains(t, ca.rootCert.Subject.Organization, "svidmint")
	assert.Equal(t, x509.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign), ca.rootCert.KeyUsage)

	// Intermediate exists and is signed by root
	assert.True(t, ca.intermediateCert.IsCA)
	assert.Equal(t, 0, ca.intermediateCert.MaxPathLen)
	assert.True(t, ca.intermediateCert.MaxPathLenZero)
	err = ca.intermediateCert.CheckSignatureFrom(ca.rootCert)
	assert.NoError(t, err)
}

func TestInitLoadsExistingCA(t *testing.T) {
	dir := t.TempDir()
	cfg := SelfSignedCAConfig{
		TrustDomain:  "example.org",
		KeyType:      "ec-p256",
		RootKeyPath:  filepath.Join(dir, "root.key"),
		RootCertPath: filepath.Join(dir, "root.crt"),
		SigningTTL:   "24h",
		DefaultTTL:   "5m",
		MaxTTL:       "1h",
	}
	ca1, err := NewSelfSignedCA(cfg)
	require.NoError(t, err)

	ca2, err := NewSelfSignedCA(cfg)
	require.NoError(t, err)

	// Same root cert
	assert.Equal(t, ca1.rootCert.Raw, ca2.rootCert.Raw)
}

func TestSignX509SVID_Valid(t *testing.T) {
	ca := newTestCA(t)
	ctx := context.Background()

	svid, err := ca.SignX509SVID(ctx, "spiffe://example.org/workload/api", nil, 300)
	require.NoError(t, err)

	// CRITICAL: Validate with go-spiffe/v2
	td := spiffeid.RequireTrustDomainFromString("example.org")
	bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{ca.rootCert})

	verifiedID, _, err := x509svid.Verify(svid.CertChain, bundle)
	require.NoError(t, err, "go-spiffe/v2 x509svid.Verify must pass")
	assert.Equal(t, "spiffe://example.org/workload/api", verifiedID.String())

	// Check cert properties per SPIFFE spec
	leaf := svid.CertChain[0]
	assert.False(t, leaf.IsCA)
	assert.Equal(t, x509.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment), leaf.KeyUsage)
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	assert.Len(t, leaf.URIs, 1)
	assert.Equal(t, "spiffe://example.org/workload/api", leaf.URIs[0].String())

	// Chain: [leaf, intermediate], no root
	assert.Len(t, svid.CertChain, 2)
	assert.True(t, svid.CertChain[1].IsCA)

	// Private key returned when no CSR
	assert.NotNil(t, svid.PrivateKey)
}

func TestSignX509SVID_WithCSR(t *testing.T) {
	ca := newTestCA(t)
	ctx := context.Background()

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, clientKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	svid, err := ca.SignX509SVID(ctx, "spiffe://example.org/workload/csr", csr, 300)
	require.NoError(t, err)

	assert.Nil(t, svid.PrivateKey)
	leafPub := svid.CertChain[0].PublicKey.(*ecdsa.PublicKey)
	assert.True(t, clientKey.PublicKey.Equal(leafPub))
}

func TestSignX509SVID_InvalidSpiffeID(t *testing.T) {
	ca := newTestCA(t)
	_, err := ca.SignX509SVID(context.Background(), "not-a-spiffe-id", nil, 300)
	assert.Error(t, err)
}

func TestSignX509SVID_WrongTrustDomain(t *testing.T) {
	ca := newTestCA(t)
	_, err := ca.SignX509SVID(context.Background(), "spiffe://wrong.domain/workload", nil, 300)
	assert.Error(t, err)
}

func TestSignJWTSVID_Valid(t *testing.T) {
	ca := newTestCA(t)
	ctx := context.Background()

	svid, err := ca.SignJWTSVID(ctx, "spiffe://example.org/workload/api", []string{"spiffe://example.org/workload/db"}, 300)
	require.NoError(t, err)
	assert.NotEmpty(t, svid.Token)

	// Validate with go-spiffe/v2's jwtsvid.ParseAndValidate
	td := spiffeid.RequireTrustDomainFromString("example.org")
	bundle := jwtbundle.FromJWTAuthorities(td, map[string]crypto.PublicKey{
		ca.jwtKeyID: &ca.jwtSigningKey.PublicKey,
	})

	parsedSVID, err := jwtsvid.ParseAndValidate(svid.Token, bundle, []string{"spiffe://example.org/workload/db"})
	require.NoError(t, err, "go-spiffe/v2 jwtsvid.ParseAndValidate must pass")
	assert.Equal(t, "spiffe://example.org/workload/api", parsedSVID.ID.String())

	// Verify no "iss" claim (SPIFFE spec: NOT RECOMMENDED)
	tok, err := jwt.ParseSigned(svid.Token, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	var claims map[string]interface{}
	err = tok.UnsafeClaimsWithoutVerification(&claims)
	require.NoError(t, err)
	assert.NotContains(t, claims, "iss", "JWT-SVID MUST NOT include 'iss' claim per SPIFFE spec")
	assert.Contains(t, claims, "sub")
	assert.Contains(t, claims, "aud")
	assert.Contains(t, claims, "exp")
	assert.Contains(t, claims, "iat")
	assert.Contains(t, claims, "jti")
}

func TestSignJWTSVID_Audience(t *testing.T) {
	ca := newTestCA(t)
	ctx := context.Background()

	svid, err := ca.SignJWTSVID(ctx, "spiffe://example.org/workload/api", []string{"aud1", "aud2"}, 300)
	require.NoError(t, err)

	tok, err := jwt.ParseSigned(svid.Token, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	var claims jwt.Claims
	err = tok.Claims(ca.jwtSigningKey.Public(), &claims)
	require.NoError(t, err)
	assert.Contains(t, []string(claims.Audience), "aud1")
	assert.Contains(t, []string(claims.Audience), "aud2")
}

func TestSignJWTSVID_InvalidSpiffeID(t *testing.T) {
	ca := newTestCA(t)
	_, err := ca.SignJWTSVID(context.Background(), "not-a-spiffe-id", []string{"aud"}, 300)
	assert.Error(t, err)
}

func TestSignJWTSVID_EmptyAudience(t *testing.T) {
	ca := newTestCA(t)
	_, err := ca.SignJWTSVID(context.Background(), "spiffe://example.org/workload/api", nil, 300)
	assert.Error(t, err)
}

func TestSignJWTSVID_WrongTrustDomain(t *testing.T) {
	ca := newTestCA(t)
	_, err := ca.SignJWTSVID(context.Background(), "spiffe://wrong.domain/workload", []string{"aud"}, 300)
	assert.Error(t, err)
}

func TestJWKS(t *testing.T) {
	ca := newTestCA(t)
	jwksBytes, err := ca.JWKS()
	require.NoError(t, err)

	var jwks jose.JSONWebKeySet
	err = json.Unmarshal(jwksBytes, &jwks)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, ca.jwtKeyID, jwks.Keys[0].KeyID)
	assert.Equal(t, "ES256", jwks.Keys[0].Algorithm)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
}

func TestGetBundle(t *testing.T) {
	ca := newTestCA(t)
	ctx := context.Background()

	bundle, err := ca.GetBundle(ctx)
	require.NoError(t, err)

	assert.Equal(t, "example.org", bundle.TrustDomain)
	require.Len(t, bundle.X509Authorities, 1)
	assert.True(t, bundle.X509Authorities[0].IsCA)
	assert.Equal(t, ca.rootCert.Raw, bundle.X509Authorities[0].Raw)

	require.Len(t, bundle.JWTAuthorities, 1)
	assert.NotEmpty(t, bundle.JWTAuthorities[0].KeyID)
	assert.NotNil(t, bundle.JWTAuthorities[0].PublicKey)
}

func TestSVIDLifetimeBounding(t *testing.T) {
	ca := newTestCA(t) // DefaultTTL=5m, MaxTTL=1h
	ctx := context.Background()

	// Requested TTL exceeds max (1h=3600s), should be bounded
	svid, err := ca.SignX509SVID(ctx, "spiffe://example.org/workload/a", nil, 7200)
	require.NoError(t, err)
	ttl := time.Until(svid.ExpiresAt).Seconds()
	assert.InDelta(t, 3600, ttl, 5)

	// TTL of 0 -> use default (5m = 300s)
	svid2, err := ca.SignX509SVID(ctx, "spiffe://example.org/workload/b", nil, 0)
	require.NoError(t, err)
	ttl2 := time.Until(svid2.ExpiresAt).Seconds()
	assert.InDelta(t, 300, ttl2, 5)
}

func TestValidateX509SVID(t *testing.T) {
	ca := newTestCA(t)
	ctx := context.Background()

	svid, err := ca.SignX509SVID(ctx, "spiffe://example.org/workload/validate-test", nil, 300)
	require.NoError(t, err)

	spiffeID, err := ca.ValidateX509SVID(ctx, svid.CertChain)
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/workload/validate-test", spiffeID)
}

func TestValidateJWTSVID(t *testing.T) {
	ca := newTestCA(t)
	ctx := context.Background()

	svid, err := ca.SignJWTSVID(ctx, "spiffe://example.org/workload/jwt-test", []string{"my-audience"}, 300)
	require.NoError(t, err)

	spiffeID, err := ca.ValidateJWTSVID(ctx, svid.Token, "my-audience")
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/workload/jwt-test", spiffeID)
}
