// Package ca implements the certificate authority for SVID issuance.
package ca

import (
	"context"
	"crypto/x509"
)

// CA defines the interface for signing and validating SVIDs.
type CA interface {
	// SignX509SVID signs a certificate signing request and returns an X.509 SVID
	// with the given SPIFFE ID and TTL (in seconds).
	SignX509SVID(ctx context.Context, spiffeID string, csr *x509.CertificateRequest, ttl int) (*X509SVID, error)

	// SignJWTSVID creates a signed JWT SVID for the given SPIFFE ID and audience
	// with the specified TTL (in seconds).
	SignJWTSVID(ctx context.Context, spiffeID string, audience []string, ttl int) (*JWTSVID, error)

	// GetBundle returns the current trust bundle containing CA certificates
	// and JWT authorities.
	GetBundle(ctx context.Context) (*TrustBundle, error)

	// ValidateX509SVID validates a chain of X.509 certificates and returns
	// the SPIFFE ID if the chain is valid.
	ValidateX509SVID(ctx context.Context, certs []*x509.Certificate) (string, error)

	// ValidateJWTSVID validates a JWT SVID token against the expected audience
	// and returns the SPIFFE ID if the token is valid.
	ValidateJWTSVID(ctx context.Context, token string, expectedAudience string) (string, error)

	// JWKS returns the JSON Web Key Set representation of the CA's public keys.
	JWKS() ([]byte, error)
}
