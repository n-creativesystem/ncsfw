package logger

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/n-creativesystem/ncsfw"
	"github.com/n-creativesystem/ncsfw/logger"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type LogFormatterParams struct {
	Request *http.Request

	// TimeStamp shows the time after the server returns a response.
	TimeStamp time.Time
	// StatusCode is HTTP response code.
	StatusCode int
	// Latency is how much time the server cost to process a certain request.
	Latency time.Duration
	// ClientIP equals Context's ClientIP method.
	ClientIP string
	// Method is the HTTP method given to the request.
	Method string
	// Path is a path the client requests.
	Path string
	// ErrorMessage is set if error has occurred in processing the request.
	ErrorMessage string
	// isTerm shows whether does gin's output descriptor refers to a terminal.
	isTerm bool
	// BodySize is the size of the Response Body
	BodySize int
	// Keys are the keys set on the request's context.
	Keys map[string]interface{}
}

func Logger(log logger.Logger) ncsfw.MiddlewareFunc {
	return func(next ncsfw.HandlerFunc) ncsfw.HandlerFunc {
		return func(c ncsfw.Context) error {
			attrKVs := make([]attribute.KeyValue, 0, 100)
			r := c.Request()
			span := trace.SpanFromContext(r.Context())
			start := time.Now()
			path := r.URL.Path
			raw := r.URL.RawQuery
			fields := make([]interface{}, 0, 100)
			requestHeader := r.Header.Clone()
			for key, value := range requestHeader {
				if len(value) >= 0 {
					k := fmt.Sprintf("req-%s", strings.ToLower(key))
					v := strings.ToLower(strings.Join(value, ", "))
					fields = append(fields, []interface{}{k, v}...)
					attrKVs = append(attrKVs, attribute.StringSlice(k, value))
				}
			}

			err := next(c)
			ctx := c.Request().Context()
			if err != nil {
				log.ErrorWithContext(r.Context(), err, fmt.Sprintf("error: %v", err))
			}

			param := LogFormatterParams{
				Request: r,
			}
			param.TimeStamp = time.Now()
			param.Latency = param.TimeStamp.Sub(start)
			param.ClientIP = c.ClientIP()
			param.Method = r.Method
			param.StatusCode = c.Writer().Status()
			if err != nil {
				param.ErrorMessage = err.Error()
			}

			param.BodySize = c.Writer().Size()

			if raw != "" {
				path = path + "?" + raw
			}

			param.Path = path
			mp := map[string]interface{}{
				"status":   param.StatusCode,
				"latency":  param.Latency,
				"clientIP": param.ClientIP,
				"method":   param.Method,
				"path":     param.Path,
				"Ua":       param.Request.UserAgent(),
			}
			for k, v := range mp {
				var attrKV attribute.KeyValue
				switch value := v.(type) {
				case string:
					attrKV = attribute.String(k, value)
				case int:
					attrKV = attribute.Int(k, value)
				case time.Duration:
					attrKV = attribute.String(k, value.String())
				}
				attrKVs = append(attrKVs, attrKV)
				fields = append(fields, []interface{}{k, v}...)
			}
			responseHeader := c.Writer().Header().Clone()
			for key, value := range responseHeader {
				if len(value) >= 0 {
					k := fmt.Sprintf("res-%s", strings.ToLower(key))
					v := strings.ToLower(strings.Join(value, ", "))
					fields = append(fields, []interface{}{k, v}...)
					attrKVs = append(attrKVs, attribute.StringSlice(k, value))
				}
			}
			if span.IsRecording() {
				span.SetAttributes(attrKVs...)
			}
			log.InfoWithContext(ctx, "incoming request", fields...)
			return err
		}
	}
}
