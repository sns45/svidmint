package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTSource_GetJWTSVID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req attestRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "jwt", req.SVIDType)
		assert.Equal(t, []string{"api.example.com"}, req.Audience)

		json.NewEncoder(w).Encode(JWTSVIDResponse{
			SpiffeID: "spiffe://example.org/workload",
			SVID: JWTSVIDData{
				Token:     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test",
				ExpiresAt: time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	src, err := NewJWTSource(
		WithServerURL(srv.URL),
		WithAttestor(&mockClientAttestor{}),
	)
	require.NoError(t, err)

	resp, err := src.GetJWTSVID(context.Background(), []string{"api.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/workload", resp.SpiffeID)
	assert.NotEmpty(t, resp.SVID.Token)
}

func TestJWTSource_EmptyAudience(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be called with empty audience")
	}))
	defer srv.Close()

	src, err := NewJWTSource(
		WithServerURL(srv.URL),
		WithAttestor(&mockClientAttestor{}),
	)
	require.NoError(t, err)

	_, err = src.GetJWTSVID(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience required")

	_, err = src.GetJWTSVID(context.Background(), []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience required")
}

func TestNewJWTSource_MissingOptions(t *testing.T) {
	_, err := NewJWTSource()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server URL required")
}
