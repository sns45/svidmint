package sdk

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// TLSClientConfig builds a *tls.Config suitable for mTLS clients using the
// X.509 SVID certificate and private key from this response.
func (r *X509SVIDResponse) TLSClientConfig() (*tls.Config, error) {
	cert, err := r.parseTLSCertificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

// TLSServerConfig builds a *tls.Config suitable for mTLS servers using the
// X.509 SVID certificate and private key from this response. It requires any
// connecting client to present a certificate.
func (r *X509SVIDResponse) TLSServerConfig() (*tls.Config, error) {
	cert, err := r.parseTLSCertificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
	}, nil
}

// parseTLSCertificate assembles a tls.Certificate from the PEM encoded cert
// chain and private key stored in the response.
func (r *X509SVIDResponse) parseTLSCertificate() (tls.Certificate, error) {
	if len(r.SVID.CertChain) == 0 {
		return tls.Certificate{}, fmt.Errorf("empty certificate chain")
	}

	chainPEM := strings.Join(r.SVID.CertChain, "\n")
	cert, err := tls.X509KeyPair([]byte(chainPEM), []byte(r.SVID.PrivateKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing TLS certificate: %w", err)
	}
	return cert, nil
}
