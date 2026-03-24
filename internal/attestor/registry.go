package attestor

import (
	"context"
	"fmt"
)

// Registry routes attestation requests to the appropriate attestor
// based on evidence type.
type Registry struct {
	attestors []Attestor
}

// NewRegistry creates a new attestor registry with the given attestors.
func NewRegistry(attestors ...Attestor) *Registry {
	return &Registry{
		attestors: attestors,
	}
}

// Attest routes the attestation request to the first attestor that
// can handle the given evidence type.
func (r *Registry) Attest(ctx context.Context, evidenceType string, evidence []byte) (*AttestationResult, error) {
	for _, a := range r.attestors {
		if a.CanAttest(evidenceType) {
			return a.Attest(ctx, evidence)
		}
	}
	return nil, fmt.Errorf("no attestor found for evidence type %q", evidenceType)
}
