package tracer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/n-creativesystem/ncsfw/version"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
)

type Tracer struct {
	tp          trace.TracerProvider
	tracer      trace.Tracer
	propagation propagation.TextMapPropagator
}

var (
	tracer *Tracer
)

type Service struct {
	Name    string
	Version string
}

func InitOpenTelemetryWithService(ctx context.Context, instrumentationName string, service Service, options ...Option) (*Tracer, error) {
	var (
		provider tracesdk.SpanExporter
		err      error
		closer   io.Closer
	)
	cfg := &config{
		exporterName: envExporterName(),
	}
	for _, opt := range options {
		opt.apply(cfg)
	}
	r := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(service.Name),
		semconv.ServiceVersionKey.String(service.Version),
	)
	switch cfg.exporterName {
	case ExporterJaeger:
		endpoint := jaeger.WithCollectorEndpoint()
		provider, err = jaeger.New(endpoint)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize Jaeger exporter: %w", err)
		}
	case ExporterJSON:
		opt := make([]stdouttrace.Option, 0, 10)
		if cfg.filename != "" {
			file, err := os.OpenFile(cfg.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return nil, fmt.Errorf("unable to open exporter file: %w", err)
			}
			opt = append(opt, stdouttrace.WithWriter(file))
			closer = file
		}
		provider, err = stdouttrace.New(opt...)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize Json exporter: %w", err)
		}
	default:
		opt := make([]stdouttrace.Option, 0, 10)
		if cfg.writer != nil {
			opt = append(opt, stdouttrace.WithWriter(cfg.writer))
			if v, ok := cfg.writer.(io.Closer); ok {
				closer = v
			}
		}
		provider, err = stdouttrace.New(opt...)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize Default exporter: %w", err)
		}
	}
	tp := tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(provider),
		tracesdk.WithSampler(tracesdk.AlwaysSample()),
		tracesdk.WithResource(r),
	)
	defer func() {
		if err != nil {
			_ = tp.Shutdown(ctx)
			if closer != nil {
				_ = closer.Close()
			}
			return
		}
		go func() {
			<-ctx.Done()
			_ = tp.Shutdown(ctx)
			if closer != nil {
				_ = closer.Close()
			}
		}()
	}()
	otel.SetTracerProvider(tp)
	b3 := b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader | b3.B3SingleHeader))
	propagation := propagation.NewCompositeTextMapPropagator(b3, propagation.TraceContext{}, propagation.Baggage{})
	otel.SetTextMapPropagator(propagation)
	tracer = &Tracer{
		tp:          tp,
		tracer:      tp.Tracer(instrumentationName),
		propagation: propagation,
	}
	return tracer, nil
}

func InitOpenTelemetry(ctx context.Context, instrumentationName string, options ...Option) (*Tracer, error) {
	s := Service{
		Name:    "ncsfw",
		Version: version.Version,
	}
	return InitOpenTelemetryWithService(ctx, instrumentationName, s, options...)
}

func TransportWrapper(rt http.RoundTripper) http.RoundTripper {
	return otelhttp.NewTransport(rt, otelhttp.WithTracerProvider(tracer.tp))
}

func NewHttpClient(rt http.RoundTripper) *http.Client {
	defaultClient := *http.DefaultClient
	defaultClient.Transport = TransportWrapper(rt)
	return &defaultClient
}

func SetHttpClient(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, NewHttpClient(nil))
}

func GetTracerProvider() trace.TracerProvider {
	return tracer.tp
}

func GetTracer() trace.Tracer {
	return tracer.tracer
}

func GetPropagation() propagation.TextMapPropagator {
	return tracer.propagation
}

func Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return tracer.tracer.Start(ctx, spanName, opts...)
}

func ContextWithSpan(c context.Context, span trace.Span) context.Context {
	return trace.ContextWithSpan(c, span)
}

func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
