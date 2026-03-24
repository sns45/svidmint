package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sns45/svidmint/internal/config"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	logger := zap.NewNop()
	srv, err := New(nil, nil, nil, &config.Config{}, logger)
	require.NoError(t, err)
	return srv
}

func TestHealthEndpoint_NilDeps(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, "healthy", resp["status"])
	assert.Equal(t, false, resp["ca_ready"])
	assert.Equal(t, false, resp["store_ready"])
}

func TestHealthEndpoint_ContentType(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestHealthEndpoint_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("POST", "/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}
