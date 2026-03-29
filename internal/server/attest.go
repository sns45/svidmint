package server

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/sns45/svidmint/internal/attestor"
)

type attestResponse struct {
	SpiffeID  string `json:"spiffe_id"`
	SVIDType  string `json:"svid_type"`
	ExpiresAt string `json:"expires_at"`

	// X.509 fields
	Certificate string `json:"certificate,omitempty"`
	CertChain   string `json:"cert_chain,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`

	// JWT fields
	Token string `json:"token,omitempty"`
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
		if len(svid.CertChain) > 0 {
			resp.Certificate = string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: svid.CertChain[0].Raw,
			}))
		}
		resp.ExpiresAt = svid.ExpiresAt.Format(time.RFC3339)
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
