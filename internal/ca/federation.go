package ca

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sns45/svidmint/internal/config"
)

// FederatedBundle pairs a trust domain name with its resolved TrustBundle.
type FederatedBundle struct {
	TrustDomain string
	Bundle      *TrustBundle
}

// BundleFetcher periodically fetches SPIFFE trust bundles from federated
// trust domain endpoints.
type BundleFetcher struct {
	configs    []config.FederationBundleConfig
	bundles    map[string]*TrustBundle
	mu         sync.RWMutex
	httpClient *http.Client
}

// spiffeBundleJSON models the SPIFFE trust bundle JSON document served by
// federation endpoints (a subset of JWK Set with x5c entries).
type spiffeBundleJSON struct {
	Keys []spiffeBundleKeyJSON `json:"keys"`
}

type spiffeBundleKeyJSON struct {
	Use string   `json:"use"`
	X5C [][]byte `json:"x5c,omitempty"`
}

// NewBundleFetcher creates a BundleFetcher for the supplied federation configs.
func NewBundleFetcher(configs []config.FederationBundleConfig) *BundleFetcher {
	return &BundleFetcher{
		configs:    configs,
		bundles:    make(map[string]*TrustBundle),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Fetch retrieves trust bundles from all configured federation endpoints and
// stores them internally. It returns the full set of fetched bundles or the
// first error encountered.
func (f *BundleFetcher) Fetch(ctx context.Context) (map[string]*TrustBundle, error) {
	result := make(map[string]*TrustBundle, len(f.configs))

	for _, cfg := range f.configs {
		bundle, err := f.fetchOne(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("fetching bundle for %s: %w", cfg.TrustDomain, err)
		}
		result[cfg.TrustDomain] = bundle
	}

	f.mu.Lock()
	for td, b := range result {
		f.bundles[td] = b
	}
	f.mu.Unlock()

	return result, nil
}

// GetBundle returns the cached TrustBundle for the given trust domain, if any.
func (f *BundleFetcher) GetBundle(trustDomain string) (*TrustBundle, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	b, ok := f.bundles[trustDomain]
	return b, ok
}

// Start runs background refresh loops for each configured federation endpoint.
// It blocks until the context is cancelled.
func (f *BundleFetcher) Start(ctx context.Context) {
	// Perform an initial fetch immediately.
	_ = f.fetchAll(ctx)

	// Determine the minimum refresh interval across all configs.
	interval := f.minRefreshInterval()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = f.fetchAll(ctx)
		}
	}
}

// fetchAll is a helper that calls Fetch and discards the returned map (the
// bundles are stored internally by Fetch).
func (f *BundleFetcher) fetchAll(ctx context.Context) error {
	_, err := f.Fetch(ctx)
	return err
}

// fetchOne retrieves and parses the SPIFFE bundle from a single endpoint.
func (f *BundleFetcher) fetchOne(ctx context.Context, cfg config.FederationBundleConfig) (*TrustBundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, cfg.Endpoint)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var bundleDoc spiffeBundleJSON
	if err := json.Unmarshal(body, &bundleDoc); err != nil {
		return nil, fmt.Errorf("decoding bundle JSON from %s: %w", cfg.Endpoint, err)
	}

	var certs []*x509.Certificate
	for _, key := range bundleDoc.Keys {
		if key.Use != "x509-svid" {
			continue
		}
		for _, raw := range key.X5C {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return nil, fmt.Errorf("parsing x5c certificate from %s: %w", cfg.Endpoint, err)
			}
			certs = append(certs, cert)
		}
	}

	return &TrustBundle{
		TrustDomain:     cfg.TrustDomain,
		X509Authorities: certs,
	}, nil
}

// minRefreshInterval returns the smallest refresh interval among all configs,
// defaulting to 5 minutes when none can be parsed.
func (f *BundleFetcher) minRefreshInterval() time.Duration {
	min := 5 * time.Minute
	for _, cfg := range f.configs {
		d, err := time.ParseDuration(cfg.RefreshInterval)
		if err != nil {
			continue
		}
		if d < min {
			min = d
		}
	}
	return min
}
