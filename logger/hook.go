package logger

import (
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/uptrace/opentelemetry-go-extra/otelutil"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

type Hook struct {
	levels []logrus.Level
}

var (
	logSeverityKey = attribute.Key("log.severity")
	logMessageKey  = attribute.Key("log.message")

	_ logrus.Hook = (*Hook)(nil)
)

func (hook *Hook) Levels() []logrus.Level {
	return hook.levels
}

func (hook *Hook) Fire(entry *logrus.Entry) error {
	ctx := entry.Context
	if ctx == nil {
		return nil
	}

	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return nil
	}

	attrs := make([]attribute.KeyValue, 0, len(entry.Data)+2+3)

	attrs = append(attrs, logSeverityKey.String(levelString(entry.Level)))
	attrs = append(attrs, logMessageKey.String(entry.Message))

	if entry.Caller != nil {
		if entry.Caller.Function != "" {
			attrs = append(attrs, semconv.CodeFunctionKey.String(entry.Caller.Function))
		}
		if entry.Caller.File != "" {
			attrs = append(attrs, semconv.CodeFilepathKey.String(entry.Caller.File))
			attrs = append(attrs, semconv.CodeLineNumberKey.Int(entry.Caller.Line))
		}
	}

	for k, v := range entry.Data {
		if k == "error" {
			if err, ok := v.(error); ok {
				typ := reflect.TypeOf(err).String()
				attrs = append(attrs, semconv.ExceptionTypeKey.String(typ))
				attrs = append(attrs, semconv.ExceptionMessageKey.String(err.Error()))
				continue
			}
		}

		attrs = append(attrs, otelutil.Attribute(k, v))
	}

	span.AddEvent("log", trace.WithAttributes(attrs...))

	if entry.Level <= logrus.ErrorLevel {
		span.SetStatus(codes.Error, entry.Message)
	}

	return nil
}

func levelString(lvl logrus.Level) string {
	s := lvl.String()
	if s == "warning" {
		s = "warn"
	}
	return strings.ToUpper(s)
}
