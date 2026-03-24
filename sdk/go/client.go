package sdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ClientAttestor gathers platform evidence for attestation.
type ClientAttestor interface {
	EvidenceType() string
	GatherEvidence(ctx context.Context) ([]byte, error)
}

// Client communicates with the svidmint server to obtain SVIDs.
type Client struct {
	serverURL  string
	attestor   ClientAttestor
	httpClient *http.Client
}

// Option configures the Client.
type Option func(*Client)

// WithServerURL sets the svidmint server URL.
func WithServerURL(url string) Option {
	return func(c *Client) { c.serverURL = url }
}

// WithAttestor sets the attestor used to gather platform evidence.
func WithAttestor(a ClientAttestor) Option {
	return func(c *Client) { c.attestor = a }
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// New creates a new Client with the given options.
func New(opts ...Option) (*Client, error) {
	c := &Client{httpClient: http.DefaultClient}
	for _, o := range opts {
		o(c)
	}
	if c.serverURL == "" {
		return nil, fmt.Errorf("server URL required")
	}
	if c.attestor == nil {
		return nil, fmt.Errorf("attestor required")
	}
	return c, nil
}

type attestRequest struct {
	EvidenceType string   `json:"evidence_type"`
	Evidence     string   `json:"evidence"`
	SVIDType     string   `json:"svid_type"`
	Audience     []string `json:"audience,omitempty"`
}

// AttestX509 performs attestation and returns an X.509 SVID.
func (c *Client) AttestX509(ctx context.Context) (*X509SVIDResponse, error) {
	evidence, err := c.attestor.GatherEvidence(ctx)
	if err != nil {
		return nil, fmt.Errorf("gathering evidence: %w", err)
	}

	reqBody := attestRequest{
		EvidenceType: c.attestor.EvidenceType(),
		Evidence:     base64.StdEncoding.EncodeToString(evidence),
		SVIDType:     "x509",
	}

	var resp X509SVIDResponse
	if err := c.doPost(ctx, "/v1/attest", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AttestJWT performs attestation and returns a JWT SVID.
func (c *Client) AttestJWT(ctx context.Context, audience []string) (*JWTSVIDResponse, error) {
	evidence, err := c.attestor.GatherEvidence(ctx)
	if err != nil {
		return nil, fmt.Errorf("gathering evidence: %w", err)
	}

	reqBody := attestRequest{
		EvidenceType: c.attestor.EvidenceType(),
		Evidence:     base64.StdEncoding.EncodeToString(evidence),
		SVIDType:     "jwt",
		Audience:     audience,
	}

	var resp JWTSVIDResponse
	if err := c.doPost(ctx, "/v1/attest", reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetBundle retrieves the trust bundle from the server.
func (c *Client) GetBundle(ctx context.Context) (*BundleResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+"/v1/bundle", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("server returned %d: %s", httpResp.StatusCode, string(body))
	}

	var resp BundleResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &resp, nil
}

func (c *Client) doPost(ctx context.Context, path string, body interface{}, result interface{}) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("server returned %d: %s", httpResp.StatusCode, string(respBody))
	}

	if err := json.NewDecoder(httpResp.Body).Decode(result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}
