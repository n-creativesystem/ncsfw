package otel

import (
	"fmt"

	"github.com/n-creativesystem/ncsfw"
	"github.com/n-creativesystem/ncsfw/tracer"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

func Middleware(serviceName string) ncsfw.MiddlewareFunc {
	return func(next ncsfw.HandlerFunc) ncsfw.HandlerFunc {
		return func(c ncsfw.Context) error {
			r := c.Request()
			ctx := c.Request().Context()
			ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(r.Header))
			fullPath := c.FullPath()
			if fullPath == "" {
				fullPath = fmt.Sprintf("HTTP %s route not found", r.Method)
			}
			opts := []trace.SpanStartOption{
				trace.WithAttributes(semconv.NetAttributesFromHTTPRequest("tcp", r)...),
				trace.WithAttributes(semconv.EndUserAttributesFromHTTPRequest(r)...),
				trace.WithAttributes(semconv.HTTPServerAttributesFromHTTPRequest(serviceName, c.FullPath(), r)...),
				trace.WithSpanKind(trace.SpanKindServer),
			}
			ctx, span := tracer.Start(ctx, fullPath, opts...)
			defer span.End()

			c.SetRequest(r.WithContext(ctx))
			err := next(c)
			if err != nil {
				span.SetStatus(codes.Error, err.Error())
			}
			status := c.Writer().Status()
			attrs := semconv.HTTPAttributesFromHTTPStatusCode(status)
			spanStatus, spanMessage := semconv.SpanStatusFromHTTPStatusCode(status)
			span.SetAttributes(attrs...)
			span.SetStatus(spanStatus, spanMessage)
			return err
		}
	}
}
