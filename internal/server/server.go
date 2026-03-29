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
	handler  http.Handler
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
	s.handler = loggingMiddleware(s.logger)(s.mux)
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /v1/bundle", s.handleBundle)
	s.mux.HandleFunc("POST /v1/validate", s.handleValidate)
	s.mux.HandleFunc("GET /v1/jwks", s.handleJWKS)
	s.mux.HandleFunc("POST /v1/attest", s.handleAttest)
}

// ServeHTTP implements http.Handler, delegating to the wrapped handler
// (which includes the logging middleware).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// Start begins listening on the configured address.
func (s *Server) Start(ctx context.Context) error {
	s.server = &http.Server{
		Addr:    s.config.Server.Listen,
		Handler: s.handler,
	}
	if s.config.Server.TLS.CertFile != "" && s.config.Server.TLS.KeyFile != "" {
		return s.server.ListenAndServeTLS(s.config.Server.TLS.CertFile, s.config.Server.TLS.KeyFile)
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
