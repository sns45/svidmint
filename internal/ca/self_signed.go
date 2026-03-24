package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// SelfSignedCAConfig holds configuration for creating a self-signed CA.
type SelfSignedCAConfig struct {
	TrustDomain  string
	KeyType      string
	RootKeyPath  string
	RootCertPath string
	SigningTTL   string
	DefaultTTL   string
	MaxTTL       string
}

// SelfSignedCA implements a self-signed certificate authority with root
// and intermediate signing keys.
type SelfSignedCA struct {
	rootKey          *ecdsa.PrivateKey
	rootCert         *x509.Certificate
	intermediateKey  *ecdsa.PrivateKey
	intermediateCert *x509.Certificate
	jwtSigningKey    *ecdsa.PrivateKey
	jwtKeyID         string
	trustDomain      string
	defaultTTL       time.Duration
	maxTTL           time.Duration
}

// NewSelfSignedCA creates or loads a self-signed CA. If root key and cert
// exist at the configured paths, they are loaded; otherwise new ones are
// generated and persisted.
func NewSelfSignedCA(cfg SelfSignedCAConfig) (*SelfSignedCA, error) {
	defaultTTL, err := time.ParseDuration(cfg.DefaultTTL)
	if err != nil {
		return nil, fmt.Errorf("parsing default TTL: %w", err)
	}
	maxTTL, err := time.ParseDuration(cfg.MaxTTL)
	if err != nil {
		return nil, fmt.Errorf("parsing max TTL: %w", err)
	}
	signingTTL, err := time.ParseDuration(cfg.SigningTTL)
	if err != nil {
		return nil, fmt.Errorf("parsing signing TTL: %w", err)
	}

	ca := &SelfSignedCA{
		trustDomain: cfg.TrustDomain,
		defaultTTL:  defaultTTL,
		maxTTL:      maxTTL,
	}

	// Try to load existing root key and cert.
	if fileExists(cfg.RootKeyPath) && fileExists(cfg.RootCertPath) {
		ca.rootKey, err = loadKey(cfg.RootKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading root key: %w", err)
		}
		ca.rootCert, err = loadCert(cfg.RootCertPath)
		if err != nil {
			return nil, fmt.Errorf("loading root cert: %w", err)
		}
	} else {
		ca.rootKey, err = generateECKey()
		if err != nil {
			return nil, fmt.Errorf("generating root key: %w", err)
		}

		ca.rootCert, err = ca.createRootCert()
		if err != nil {
			return nil, fmt.Errorf("creating root cert: %w", err)
		}

		if err := saveKey(cfg.RootKeyPath, ca.rootKey); err != nil {
			return nil, fmt.Errorf("saving root key: %w", err)
		}
		if err := saveCert(cfg.RootCertPath, ca.rootCert); err != nil {
			return nil, fmt.Errorf("saving root cert: %w", err)
		}
	}

	// Generate intermediate signing key and cert (always fresh).
	ca.intermediateKey, err = generateECKey()
	if err != nil {
		return nil, fmt.Errorf("generating intermediate key: %w", err)
	}
	ca.intermediateCert, err = ca.createIntermediateCert(signingTTL)
	if err != nil {
		return nil, fmt.Errorf("creating intermediate cert: %w", err)
	}

	// Generate JWT signing key.
	ca.jwtSigningKey, err = generateECKey()
	if err != nil {
		return nil, fmt.Errorf("generating JWT signing key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&ca.jwtSigningKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling JWT public key: %w", err)
	}
	hash := sha256.Sum256(pubDER)
	ca.jwtKeyID = hex.EncodeToString(hash[:])[:16]

	return ca, nil
}

func (ca *SelfSignedCA) createRootCert() (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "svidmint Root CA",
			Organization: []string{"svidmint"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &ca.rootKey.PublicKey, ca.rootKey)
	if err != nil {
		return nil, fmt.Errorf("creating root certificate: %w", err)
	}

	return x509.ParseCertificate(certDER)
}

func (ca *SelfSignedCA) createIntermediateCert(signingTTL time.Duration) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "svidmint Intermediate CA",
			Organization: []string{"svidmint"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(signingTTL),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.rootCert, &ca.intermediateKey.PublicKey, ca.rootKey)
	if err != nil {
		return nil, fmt.Errorf("creating intermediate certificate: %w", err)
	}

	return x509.ParseCertificate(certDER)
}

func generateECKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func randomSerial() (*big.Int, error) {
	serial := make([]byte, 16)
	if _, err := rand.Read(serial); err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	return new(big.Int).SetBytes(serial), nil
}

func saveKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func saveCert(path string, cert *x509.Certificate) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA")
	}
	return ecKey, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// SignX509SVID creates and signs an X.509 SVID for the given SPIFFE ID.
// If csr is nil, a new ECDSA P-256 key pair is generated and the private key
// is returned in the result. If csr is provided, its public key is used and
// PrivateKey in the result will be nil.
func (ca *SelfSignedCA) SignX509SVID(ctx context.Context, spiffeID string, csr *x509.CertificateRequest, ttl int) (*X509SVID, error) {
	// Validate SPIFFE ID
	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}
	if id.TrustDomain().String() != ca.trustDomain {
		return nil, fmt.Errorf("trust domain mismatch: got %s, want %s", id.TrustDomain(), ca.trustDomain)
	}
	if id.Path() == "" {
		return nil, fmt.Errorf("SPIFFE ID must have a non-root path")
	}

	// Key handling: use CSR public key or generate a fresh key pair
	var pubKey crypto.PublicKey
	var privKey any
	if csr != nil {
		pubKey = csr.PublicKey
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating workload key: %w", err)
		}
		pubKey = &key.PublicKey
		privKey = key
	}

	// Compute effective TTL
	effectiveTTL := ca.computeTTL(ttl, 0, time.Time{})

	// Build leaf certificate template
	serialNumber, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}
	spiffeURI, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("parsing SPIFFE ID as URI: %w", err)
	}
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		URIs:                  []*url.URL{spiffeURI},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(effectiveTTL) * time.Second),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	// Sign with the intermediate CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.intermediateCert, pubKey, ca.intermediateKey)
	if err != nil {
		return nil, fmt.Errorf("signing leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing signed certificate: %w", err)
	}

	return &X509SVID{
		SpiffeID:   spiffeID,
		CertChain:  []*x509.Certificate{leaf, ca.intermediateCert},
		PrivateKey: privKey,
		ExpiresAt:  template.NotAfter,
	}, nil
}

// computeTTL returns the effective TTL in seconds by taking the minimum of:
// the requested TTL (or default if 0), the entry TTL (if > 0), the remaining
// platform token validity (if non-zero), and the global max TTL.
func (ca *SelfSignedCA) computeTTL(requestedTTL int, entryTTL int, platformExpiry time.Time) int {
	effective := ca.defaultTTL
	if requestedTTL > 0 {
		effective = time.Duration(requestedTTL) * time.Second
	}
	if entryTTL > 0 {
		entryDur := time.Duration(entryTTL) * time.Second
		if entryDur < effective {
			effective = entryDur
		}
	}
	if !platformExpiry.IsZero() {
		remaining := time.Until(platformExpiry)
		if remaining > 0 && remaining < effective {
			effective = remaining
		}
	}
	if effective > ca.maxTTL {
		effective = ca.maxTTL
	}
	if effective <= 0 {
		effective = ca.defaultTTL
	}
	return int(effective.Seconds())
}

// SignJWTSVID creates a signed JWT SVID for the given SPIFFE ID and audience
// with the specified TTL (in seconds). The token uses ES256 and does NOT
// include the "iss" claim per the SPIFFE specification.
func (ca *SelfSignedCA) SignJWTSVID(ctx context.Context, spiffeID string, audience []string, ttl int) (*JWTSVID, error) {
	// Validate SPIFFE ID
	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}
	if id.TrustDomain().String() != ca.trustDomain {
		return nil, fmt.Errorf("trust domain mismatch: got %s, want %s", id.TrustDomain(), ca.trustDomain)
	}
	if id.Path() == "" {
		return nil, fmt.Errorf("SPIFFE ID must have a non-root path")
	}

	// Require non-empty audience
	if len(audience) == 0 {
		return nil, fmt.Errorf("audience must not be empty")
	}

	// Compute effective TTL
	effectiveTTL := ca.computeTTL(ttl, 0, time.Time{})

	// Build signer with kid header
	signerOpts := (&jose.SignerOptions{}).WithHeader("kid", ca.jwtKeyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: ca.jwtSigningKey}, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("creating JWT signer: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(effectiveTTL) * time.Second)

	// Build claims map manually to avoid including "iss"
	claims := map[string]interface{}{
		"sub": spiffeID,
		"aud": audience,
		"exp": josejwt.NewNumericDate(expiresAt),
		"iat": josejwt.NewNumericDate(now),
		"jti": uuid.New().String(),
	}

	token, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return nil, fmt.Errorf("signing JWT: %w", err)
	}

	return &JWTSVID{
		SpiffeID:  spiffeID,
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// GetBundle returns the current trust bundle containing the root CA certificate
// and JWT signing public key.
func (ca *SelfSignedCA) GetBundle(ctx context.Context) (*TrustBundle, error) {
	return &TrustBundle{
		TrustDomain:     ca.trustDomain,
		X509Authorities: []*x509.Certificate{ca.rootCert},
		JWTAuthorities: []JWTAuthority{
			{
				KeyID:     ca.jwtKeyID,
				PublicKey: ca.jwtSigningKey.Public(),
			},
		},
		SequenceNumber: 1,
	}, nil
}

// JWKS returns the JSON Web Key Set containing the CA's JWT signing public key.
func (ca *SelfSignedCA) JWKS() ([]byte, error) {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     ca.jwtKeyID,
				Key:       &ca.jwtSigningKey.PublicKey,
				Algorithm: string(jose.ES256),
				Use:       "sig",
			},
		},
	}
	return json.Marshal(jwks)
}

// ValidateX509SVID validates a chain of X.509 certificates against the CA's
// root certificate using go-spiffe/v2 and returns the SPIFFE ID if valid.
func (ca *SelfSignedCA) ValidateX509SVID(ctx context.Context, certs []*x509.Certificate) (string, error) {
	td, err := spiffeid.TrustDomainFromString(ca.trustDomain)
	if err != nil {
		return "", fmt.Errorf("parsing trust domain: %w", err)
	}
	bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{ca.rootCert})

	verifiedID, _, err := x509svid.Verify(certs, bundle)
	if err != nil {
		return "", fmt.Errorf("verifying X.509 SVID: %w", err)
	}
	return verifiedID.String(), nil
}

// ValidateJWTSVID validates a JWT SVID token against the expected audience
// using go-spiffe/v2 and returns the SPIFFE ID if valid.
func (ca *SelfSignedCA) ValidateJWTSVID(ctx context.Context, token string, expectedAudience string) (string, error) {
	td, err := spiffeid.TrustDomainFromString(ca.trustDomain)
	if err != nil {
		return "", fmt.Errorf("parsing trust domain: %w", err)
	}
	bundle := jwtbundle.FromJWTAuthorities(td, map[string]crypto.PublicKey{
		ca.jwtKeyID: &ca.jwtSigningKey.PublicKey,
	})

	parsedSVID, err := jwtsvid.ParseAndValidate(token, bundle, []string{expectedAudience})
	if err != nil {
		return "", fmt.Errorf("validating JWT SVID: %w", err)
	}
	return parsedSVID.ID.String(), nil
}
