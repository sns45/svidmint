package attestor

import "context"

type Attestor interface {
	Name() string
	Attest(ctx context.Context, evidence []byte) (*AttestationResult, error)
	CanAttest(evidenceType string) bool
}
