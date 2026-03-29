package server

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"time"
)

type validateRequest struct {
	SVIDType string `json:"svid_type"`
	SVID     string `json:"svid"`
}

type validateResponse struct {
	Valid    bool   `json:"valid"`
	SpiffeID string `json:"spiffe_id,omitempty"`
	// ExpiresAt is a Unix timestamp; omitted when zero.
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req validateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	switch req.SVIDType {
	case "x509":
		s.validateX509(w, r, req.SVID)
	case "jwt":
		s.validateJWT(w, r, req.SVID)
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "svid_type must be x509 or jwt")
	}
}

func (s *Server) validateX509(w http.ResponseWriter, r *http.Request, pemData string) {
	var certs []*x509.Certificate
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			writeJSON(w, http.StatusOK, validateResponse{Valid: false, Error: "invalid certificate PEM"})
			return
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		svidValidatedTotal.WithLabelValues("x509", "false").Inc()
		writeJSON(w, http.StatusOK, validateResponse{Valid: false, Error: "no certificates found in PEM data"})
		return
	}

	spiffeID, err := s.ca.ValidateX509SVID(r.Context(), certs)
	if err != nil {
		svidValidatedTotal.WithLabelValues("x509", "false").Inc()
		writeJSON(w, http.StatusOK, validateResponse{Valid: false, Error: err.Error()})
		return
	}

	svidValidatedTotal.WithLabelValues("x509", "true").Inc()
	writeJSON(w, http.StatusOK, validateResponse{
		Valid:     true,
		SpiffeID:  spiffeID,
		ExpiresAt: certs[0].NotAfter.Unix(),
	})
}

func (s *Server) validateJWT(w http.ResponseWriter, r *http.Request, token string) {
	spiffeID, err := s.ca.ValidateJWTSVID(r.Context(), token, "")
	if err != nil {
		svidValidatedTotal.WithLabelValues("jwt", "false").Inc()
		writeJSON(w, http.StatusOK, validateResponse{Valid: false, Error: err.Error()})
		return
	}

	svidValidatedTotal.WithLabelValues("jwt", "true").Inc()
	// We don't have expiry info from the CA interface directly for JWT,
	// so we return the current validation result without expires_at.
	_ = time.Now() // placeholder; the CA could be extended to return expiry
	writeJSON(w, http.StatusOK, validateResponse{
		Valid:    true,
		SpiffeID: spiffeID,
	})
}
