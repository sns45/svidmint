package sdk

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Compile-time interface checks: X509Source implements both go-spiffe/v2
// source interfaces, making it a drop-in replacement for workloadapi.NewX509Source().
var _ x509svid.Source = (*X509Source)(nil)
var _ x509bundle.Source = (*X509Source)(nil)

// X509Source provides X.509 SVIDs and trust bundles by attesting against
// a svidmint server. It implements x509svid.Source and x509bundle.Source
// from go-spiffe/v2.
type X509Source struct {
	client *Client
	mu     sync.RWMutex
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
	cancel context.CancelFunc
	closed bool
}

// NewX509Source creates an X509Source that immediately attests against
// the svidmint server and starts a background goroutine to refresh
// the SVID at 50% of its lifetime.
func NewX509Source(ctx context.Context, opts ...Option) (*X509Source, error) {
	client, err := New(opts...)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	s := &X509Source{
		client: client,
		cancel: cancel,
	}

	// Initial attestation and bundle fetch
	if err := s.refresh(ctx); err != nil {
		cancel()
		return nil, err
	}

	// Start background refresh
	go s.refreshLoop(ctx)

	return s, nil
}

// GetX509SVID returns the current X.509 SVID. This satisfies x509svid.Source.
func (s *X509Source) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errors.New("x509source: source is closed")
	}
	if s.svid == nil {
		return nil, errors.New("x509source: no SVID available")
	}
	return s.svid, nil
}

// GetX509BundleForTrustDomain returns the trust bundle. This satisfies x509bundle.Source.
func (s *X509Source) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errors.New("x509source: source is closed")
	}
	if s.bundle == nil {
		return nil, errors.New("x509source: no bundle available")
	}
	return s.bundle, nil
}

// Close stops the background refresh goroutine and marks the source as closed.
func (s *X509Source) Close() error {
	s.cancel()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

// refresh performs attestation and fetches the trust bundle, then parses
// both into go-spiffe/v2 types.
func (s *X509Source) refresh(ctx context.Context) error {
	// Attest to get SVID
	resp, err := s.client.AttestX509(ctx)
	if err != nil {
		return err
	}

	svid, err := parseSVIDResponse(resp)
	if err != nil {
		return err
	}

	// Fetch trust bundle
	bundleResp, err := s.client.GetBundle(ctx)
	if err != nil {
		return err
	}

	bundle, err := parseBundleResponse(bundleResp)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.svid = svid
	s.bundle = bundle
	s.mu.Unlock()

	return nil
}

// refreshLoop re-attests at 50% of the SVID's remaining lifetime.
func (s *X509Source) refreshLoop(ctx context.Context) {
	for {
		s.mu.RLock()
		if s.closed || s.svid == nil || len(s.svid.Certificates) == 0 {
			s.mu.RUnlock()
			return
		}
		expiry := s.svid.Certificates[0].NotAfter
		halfLife := time.Until(expiry) / 2
		s.mu.RUnlock()

		if halfLife <= 0 {
			halfLife = 1 * time.Second
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(halfLife):
			_ = s.refresh(ctx)
		}
	}
}

// parseSVIDResponse converts the svidmint API response into a go-spiffe/v2 SVID.
func parseSVIDResponse(resp *X509SVIDResponse) (*x509svid.SVID, error) {
	if len(resp.SVID.CertChain) == 0 {
		return nil, errors.New("x509source: empty certificate chain in response")
	}

	var certs []*x509.Certificate
	for _, certPEM := range resp.SVID.CertChain {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return nil, errors.New("x509source: failed to decode PEM certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("x509source: failed to parse certificate: " + err.Error())
		}
		certs = append(certs, cert)
	}

	// Parse private key
	if resp.SVID.PrivateKey == "" {
		return nil, errors.New("x509source: no private key in response")
	}
	block, _ := pem.Decode([]byte(resp.SVID.PrivateKey))
	if block == nil {
		return nil, errors.New("x509source: failed to decode PEM private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("x509source: failed to parse EC private key: " + err.Error())
	}

	// Parse SPIFFE ID from the response
	id, err := spiffeid.FromString(resp.SpiffeID)
	if err != nil {
		return nil, errors.New("x509source: invalid SPIFFE ID: " + err.Error())
	}

	return &x509svid.SVID{
		ID:           id,
		Certificates: certs,
		PrivateKey:   key,
	}, nil
}

// parseBundleResponse converts the svidmint API bundle response into a go-spiffe/v2 bundle.
func parseBundleResponse(resp *BundleResponse) (*x509bundle.Bundle, error) {
	td, err := spiffeid.TrustDomainFromString(resp.TrustDomain)
	if err != nil {
		return nil, errors.New("x509source: invalid trust domain: " + err.Error())
	}

	var authorities []*x509.Certificate
	for _, certPEM := range resp.X509Authorities {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return nil, errors.New("x509source: failed to decode PEM authority certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("x509source: failed to parse authority certificate: " + err.Error())
		}
		authorities = append(authorities, cert)
	}

	return x509bundle.FromX509Authorities(td, authorities), nil
}
