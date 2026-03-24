package server

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

var (
	attestationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{Name: "workload_id_attestation_total", Help: "Total attestation attempts"},
		[]string{"attestor", "status"},
	)
	attestationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{Name: "workload_id_attestation_duration_seconds", Help: "Attestation duration"},
		[]string{"attestor"},
	)
	svidIssuedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{Name: "workload_id_svid_issued_total", Help: "Total SVIDs issued"},
		[]string{"svid_type", "attestor"},
	)
	svidValidatedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{Name: "workload_id_svid_validated_total", Help: "Total SVIDs validated"},
		[]string{"svid_type", "valid"},
	)
	activeEntries = promauto.NewGauge(
		prometheus.GaugeOpts{Name: "workload_id_active_entries", Help: "Number of active registration entries"},
	)
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			logger.Info("request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", sw.status),
				zap.Duration("duration", time.Since(start)),
			)
		})
	}
}
