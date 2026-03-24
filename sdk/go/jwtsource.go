package sdk

import (
	"context"
	"fmt"
)

// JWTSource provides JWT SVIDs by performing attestation against the svidmint server.
type JWTSource struct {
	client *Client
}

// NewJWTSource creates a JWTSource backed by a new Client configured with the given options.
func NewJWTSource(opts ...Option) (*JWTSource, error) {
	client, err := New(opts...)
	if err != nil {
		return nil, err
	}
	return &JWTSource{client: client}, nil
}

// GetJWTSVID obtains a JWT SVID for the given audience list.
// At least one audience value is required.
func (s *JWTSource) GetJWTSVID(ctx context.Context, audience []string) (*JWTSVIDResponse, error) {
	if len(audience) == 0 {
		return nil, fmt.Errorf("audience required")
	}
	return s.client.AttestJWT(ctx, audience)
}
