package metrics

import (
	"strings"
	"time"

	"github.com/n-creativesystem/ncsfw"
	"github.com/n-creativesystem/ncsfw/tracer/metrics"
)

type MetricsMiddleware func(handler string) ncsfw.MiddlewareFunc

func RequestMetrics(cfg *Config) MetricsMiddleware {
	return func(handler string) ncsfw.MiddlewareFunc {
		return func(next ncsfw.HandlerFunc) ncsfw.HandlerFunc {
			return func(c ncsfw.Context) error {
				now := time.Now()
				HttpRequestsInFlight.Inc()
				defer HttpRequestsInFlight.Dec()
				err := next(c)
				status := c.Writer().Status()
				r := c.Request()
				code := SanitizeCode(status)
				method := SanitizeMethod(r.Method)
				duration := time.Since(now).Nanoseconds() / int64(time.Millisecond)
				metrics.MHttpRequestTotal.WithLabelValues(handler, code, method).Inc()
				metrics.MHttpRequestSummary.WithLabelValues(handler, code, method).Observe(float64(duration))
				switch {
				case strings.HasPrefix(r.RequestURI, cfg.GRPCPrefix):
					CountGRPCRequests(status)
				case strings.HasPrefix(r.RequestURI, cfg.RestPrefix):
					CountApiRequests(status)
				default:
					CountPageRequests(status)
				}
				return err
			}
		}
	}
}
