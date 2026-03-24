package sdk

// X509SVIDResponse represents the server response for an X.509 SVID attestation.
type X509SVIDResponse struct {
	SpiffeID string       `json:"spiffe_id"`
	SVID     X509SVIDData `json:"svid"`
}

// X509SVIDData contains the X.509 certificate chain and optional private key.
type X509SVIDData struct {
	CertChain  []string `json:"cert_chain"`
	PrivateKey string   `json:"private_key,omitempty"`
	ExpiresAt  string   `json:"expires_at"`
}

// JWTSVIDResponse represents the server response for a JWT SVID attestation.
type JWTSVIDResponse struct {
	SpiffeID string      `json:"spiffe_id"`
	SVID     JWTSVIDData `json:"svid"`
}

// JWTSVIDData contains the JWT token and its expiration.
type JWTSVIDData struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// BundleResponse represents the trust bundle returned by the server.
type BundleResponse struct {
	TrustDomain     string        `json:"trust_domain"`
	X509Authorities []string      `json:"x509_authorities,omitempty"`
	JWTAuthorities  []interface{} `json:"jwt_authorities,omitempty"`
	RefreshHint     int           `json:"refresh_hint"`
	SequenceNumber  int64         `json:"sequence_number"`
}
