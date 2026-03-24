// Package server implements the svidmint HTTP server.
package server

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/sns45/svidmint/internal/attestor"
	"github.com/sns45/svidmint/internal/ca"
	"github.com/sns45/svidmint/internal/config"
	"github.com/sns45/svidmint/internal/entry"
)

// Server is the main HTTP server for svidmint, hosting the attestation,
// SVID issuance, and management API.
type Server struct {
	ca       ca.CA
	registry *attestor.Registry
	store    entry.Store
	config   *config.Config
	logger   *zap.Logger
	mux      *http.ServeMux
	server   *http.Server
}

// New creates a new Server with the provided dependencies.
func New(caImpl ca.CA, registry *attestor.Registry, store entry.Store, cfg *config.Config, logger *zap.Logger) (*Server, error) {
	s := &Server{
		ca:       caImpl,
		registry: registry,
		store:    store,
		config:   cfg,
		logger:   logger,
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /v1/bundle", s.handleBundle)
	s.mux.HandleFunc("POST /v1/validate", s.handleValidate)
	s.mux.HandleFunc("GET /v1/jwks", s.handleJWKS)
	s.mux.HandleFunc("POST /v1/attest", s.handleAttest)
}

// ServeHTTP implements http.Handler, delegating to the internal mux.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// Start begins listening on the configured address.
func (s *Server) Start(ctx context.Context) error {
	s.server = &http.Server{
		Addr:    s.config.Server.Listen,
		Handler: s.mux,
	}
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}
