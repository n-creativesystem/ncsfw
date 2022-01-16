package logger

import (
	"context"

	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
)

type contextKey struct{}

var ctxKey contextKey

func ToContext(ctx context.Context, log Logger) context.Context {
	return context.WithValue(ctx, ctxKey, log)
}

func Extract(ctx context.Context) Logger {
	log := FromContext(ctx)
	tags := grpc_ctxtags.Extract(ctx)
	values := tags.Values()
	for k, v := range values {
		log = log.AddParam(k, v)
	}
	return log
}

func FromContext(ctx context.Context) Logger {
	return ctx.Value(ctxKey).(Logger)
}
