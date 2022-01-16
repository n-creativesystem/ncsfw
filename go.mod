module github.com/n-creativesystem/ncsfw

go 1.16

require (
	github.com/go-playground/validator/v10 v10.10.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/prometheus/client_golang v1.11.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/uptrace/opentelemetry-go-extra/otelutil v0.1.7
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.28.0
	go.opentelemetry.io/contrib/propagators/b3 v1.3.0
	go.opentelemetry.io/otel v1.3.0
	go.opentelemetry.io/otel/exporters/jaeger v1.3.0
	go.opentelemetry.io/otel/exporters/prometheus v0.26.0
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.3.0
	go.opentelemetry.io/otel/metric v0.26.0
	go.opentelemetry.io/otel/sdk v1.3.0
	go.opentelemetry.io/otel/sdk/export/metric v0.26.0
	go.opentelemetry.io/otel/sdk/metric v0.26.0
	go.opentelemetry.io/otel/trace v1.3.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	google.golang.org/grpc v1.43.0
)
