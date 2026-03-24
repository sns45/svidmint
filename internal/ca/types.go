package ca

import (
	"crypto/x509"
	"time"
)

type X509SVID struct {
	SpiffeID   string
	CertChain  []*x509.Certificate
	PrivateKey any
	ExpiresAt  time.Time
}

type JWTSVID struct {
	SpiffeID  string
	Token     string
	ExpiresAt time.Time
}

type TrustBundle struct {
	TrustDomain     string
	X509Authorities []*x509.Certificate
	JWTAuthorities  []JWTAuthority
	SequenceNumber  int64
}

type JWTAuthority struct {
	KeyID     string
	PublicKey any
}
