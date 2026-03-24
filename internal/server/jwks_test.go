package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKSEndpoint_ReturnsValidJSON(t *testing.T) {
	jwksJSON := `{"keys":[{"kty":"EC","kid":"key1","crv":"P-256","x":"abc","y":"def"}]}`
	mock := &mockCA{
		jwksData: []byte(jwksJSON),
	}
	srv := newTestServerWithMocks(t, mock, &mockStore{})

	req := httptest.NewRequest("GET", "/v1/jwks", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var parsed map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &parsed)
	require.NoError(t, err)

	keys, ok := parsed["keys"].([]interface{})
	require.True(t, ok)
	assert.Len(t, keys, 1)
}

func TestJWKSEndpoint_CAError(t *testing.T) {
	mock := &mockCA{
		jwksErr: errors.New("key store unavailable"),
	}
	srv := newTestServerWithMocks(t, mock, &mockStore{})

	req := httptest.NewRequest("GET", "/v1/jwks", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestJWKSEndpoint_MethodNotAllowed(t *testing.T) {
	mock := &mockCA{jwksData: []byte(`{}`)}
	srv := newTestServerWithMocks(t, mock, &mockStore{})

	req := httptest.NewRequest("POST", "/v1/jwks", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}
