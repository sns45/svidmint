package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestLoggingMiddleware_LogsRequestFields(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	handler := loggingMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	fields := make(map[string]interface{})
	for _, f := range entry.Context {
		fields[f.Key] = f.String
	}
	assert.Equal(t, "GET", fields["method"])
	assert.Equal(t, "/v1/health", fields["path"])
}

func TestLoggingMiddleware_CapturesStatusCode(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	handler := loggingMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	req := httptest.NewRequest("POST", "/v1/mint", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	for _, f := range entry.Context {
		if f.Key == "status" {
			assert.Equal(t, int64(http.StatusNotFound), f.Integer)
		}
	}
}

func TestLoggingMiddleware_DefaultStatus200(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	handler := loggingMiddleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No explicit WriteHeader call; should default to 200
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	for _, f := range entry.Context {
		if f.Key == "status" {
			assert.Equal(t, int64(http.StatusOK), f.Integer)
		}
	}
}

func TestMetrics_AttestationCounterExists(t *testing.T) {
	// Verify the counters are registered and can be incremented without panic
	attestationTotal.WithLabelValues("aws_sts", "success").Inc()
	svidIssuedTotal.WithLabelValues("x509", "aws_sts").Inc()
	svidValidatedTotal.WithLabelValues("jwt", "true").Inc()
	activeEntries.Set(5)
}

func TestMetrics_AttestationDurationHistogram(t *testing.T) {
	// Verify histogram can observe values without panic
	attestationDuration.WithLabelValues("aws_lambda").Observe(0.042)
}
