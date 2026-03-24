package server

import "net/http"

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"status":      "healthy",
		"ca_ready":    s.ca != nil,
		"store_ready": s.store != nil,
	}
	writeJSON(w, http.StatusOK, resp)
}
