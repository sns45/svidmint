package server

import "net/http"

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	data, err := s.ca.JWKS()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "jwks_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
