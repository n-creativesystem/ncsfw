package metrics

import (
	"strconv"
	"strings"

	"github.com/n-creativesystem/ncsfw/tracer/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	HttpRequestsInFlight         prometheus.Gauge
	HttpRequestDurationHistogram *prometheus.HistogramVec

	defBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}
)

func init() {
	HttpRequestsInFlight = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "grafana",
			Name:      "http_request_in_flight",
			Help:      "A gauge of requests currently being served by Grafana.",
		},
	)
	HttpRequestDurationHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "grafana",
			Name:      "http_request_duration_seconds",
			Help:      "Histogram of latencies for HTTP requests.",
			Buckets:   defBuckets,
		},
		[]string{"handler", "status_code", "method"},
	)

	prometheus.MustRegister(HttpRequestsInFlight, HttpRequestDurationHistogram)
}

func CountApiRequests(status int) {
	switch status {
	case 200:
		metrics.MApiStatus.WithLabelValues("200").Inc()
	case 400:
		metrics.MApiStatus.WithLabelValues("400").Inc()
	case 404:
		metrics.MApiStatus.WithLabelValues("404").Inc()
	case 500:
		metrics.MApiStatus.WithLabelValues("500").Inc()
	default:
		metrics.MApiStatus.WithLabelValues("unknown").Inc()
	}
}

func CountPageRequests(status int) {
	switch status {
	case 200:
		metrics.MPageStatus.WithLabelValues("200").Inc()
	case 400:
		metrics.MPageStatus.WithLabelValues("400").Inc()
	case 404:
		metrics.MPageStatus.WithLabelValues("404").Inc()
	case 500:
		metrics.MPageStatus.WithLabelValues("500").Inc()
	default:
		metrics.MPageStatus.WithLabelValues("unknown").Inc()
	}
}

func CountGRPCRequests(status int) {
	switch status {
	case 200:
		metrics.MGRPCStatus.WithLabelValues("200").Inc()
	case 400:
		metrics.MGRPCStatus.WithLabelValues("400").Inc()
	case 404:
		metrics.MGRPCStatus.WithLabelValues("404").Inc()
	case 500:
		metrics.MGRPCStatus.WithLabelValues("500").Inc()
	default:
		metrics.MGRPCStatus.WithLabelValues("unknown").Inc()
	}
}

func SanitizeMethod(m string) string {
	return strings.ToLower(m)
}

func SanitizeCode(s int) string {
	if s == 0 {
		return "200"
	}
	return strconv.Itoa(s)
}
