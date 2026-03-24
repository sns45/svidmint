package attestor

import "time"

type AttestationResult struct {
	Claims      map[string]string
	ExpiresAt   time.Time
	RawIdentity string
}

type AttestRequest struct {
	EvidenceType string   `json:"evidence_type"`
	Evidence     string   `json:"evidence"`
	SVIDType     string   `json:"svid_type"`
	Audience     []string `json:"audience,omitempty"`
	CSR          string   `json:"csr,omitempty"`
}
