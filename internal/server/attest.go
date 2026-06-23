package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/sns45/svidmint/internal/attestor"
)

// x509SVIDData mirrors the SDK's X509SVIDData type so the JSON contract is
// identical on both sides of the wire.
type x509SVIDData struct {
	CertChain  []string `json:"cert_chain"`
	PrivateKey string   `json:"private_key,omitempty"`
	ExpiresAt  string   `json:"expires_at"`
}

type attestResponse struct {
	SpiffeID string `json:"spiffe_id"`
	SVIDType string `json:"svid_type"`

	// X.509 fields — nested under "svid" to match the Go SDK's X509SVIDResponse.
	SVID *x509SVIDData `json:"svid,omitempty"`

	// JWT fields
	ExpiresAt string `json:"expires_at,omitempty"`
	Token     string `json:"token,omitempty"`
}

func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	var req attestor.AttestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	// Validate required fields.
	if req.EvidenceType == "" || req.Evidence == "" || req.SVIDType == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "evidence_type, evidence, and svid_type are required")
		return
	}

	if req.SVIDType != "x509" && req.SVIDType != "jwt" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "svid_type must be x509 or jwt")
		return
	}

	if req.SVIDType == "jwt" && len(req.Audience) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "audience is required for jwt svid_type")
		return
	}

	// Base64 decode the evidence.
	evidence, err := base64.StdEncoding.DecodeString(req.Evidence)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "evidence must be valid base64")
		return
	}

	// Attest the evidence via the registry.
	attestStart := time.Now()
	result, err := s.registry.Attest(r.Context(), req.EvidenceType, evidence)
	if err != nil {
		attestationTotal.WithLabelValues("unknown", "error").Inc()
		writeError(w, http.StatusUnauthorized, "ATTESTATION_FAILED", err.Error())
		return
	}
	attestationDuration.WithLabelValues(req.EvidenceType).Observe(time.Since(attestStart).Seconds())

	// Match against registration entries.
	matchedEntry, err := s.store.Match(r.Context(), req.EvidenceType, result.Claims)
	if err != nil || matchedEntry == nil {
		writeError(w, http.StatusForbidden, "NO_MATCHING_ENTRY", "no matching registration entry found")
		return
	}

	// Compute effective TTL.
	ttl := matchedEntry.TTL
	if ttl <= 0 {
		ttl = 3600 // default 1 hour
	}

	// Issue the SVID.
	resp := attestResponse{
		SpiffeID: matchedEntry.SpiffeID,
		SVIDType: req.SVIDType,
	}

	switch req.SVIDType {
	case "x509":
		svid, err := s.ca.SignX509SVID(r.Context(), matchedEntry.SpiffeID, nil, ttl)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "SVID_ISSUANCE_FAILED", err.Error())
			return
		}

		// Encode every certificate in the chain (leaf first, intermediates
		// after; root excluded per SPIFFE spec) as a PEM string.
		chainPEMs := make([]string, 0, len(svid.CertChain))
		for _, cert := range svid.CertChain {
			chainPEMs = append(chainPEMs, string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})))
		}

		// Encode the private key when the CA generated one (csr == nil path).
		// The CA holds the client key only because it generated it on the
		// workload's behalf; this is intentional for serverless environments
		// where the workload cannot generate its own key material.
		var privKeyPEM string
		if svid.PrivateKey != nil {
			privKeyPEM = encodePrivateKey(svid.PrivateKey)
		}

		resp.SVID = &x509SVIDData{
			CertChain:  chainPEMs,
			PrivateKey: privKeyPEM,
			ExpiresAt:  svid.ExpiresAt.Format(time.RFC3339),
		}
	case "jwt":
		svid, err := s.ca.SignJWTSVID(r.Context(), matchedEntry.SpiffeID, req.Audience, ttl)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "SVID_ISSUANCE_FAILED", err.Error())
			return
		}
		resp.Token = svid.Token
		resp.ExpiresAt = svid.ExpiresAt.Format(time.RFC3339)
	}

	attestationTotal.WithLabelValues(req.EvidenceType, "success").Inc()
	svidIssuedTotal.WithLabelValues(req.SVIDType, req.EvidenceType).Inc()
	writeJSON(w, http.StatusOK, resp)
}

// encodePrivateKey PEM-encodes a private key. Only ECDSA keys are supported
// because the CA only generates ECDSA P-256 keys.
func encodePrivateKey(key any) string {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return ""
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}
