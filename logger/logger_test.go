package logger_test

import (
	"context"
	"errors"
	"testing"

	"github.com/n-creativesystem/ncsfw/logger"
	"github.com/n-creativesystem/ncsfw/tracer"
	"github.com/n-creativesystem/ncsfw/version"
)

func TestLogger(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _ = tracer.InitOpenTelemetryWithService(ctx, "github.com/n-creativesystem/", tracer.Service{
		Name:    "rbns",
		Version: version.Version,
	})
	ctx, span := tracer.Start(ctx, "test span")
	defer span.End()
	log()
	defer func() {
		_ = recover()
	}()
	module := logger.New("mainModule", logger.WithExitFunc(func(i int) {}))
	module.AddParam("key", "module").TraceWithContext(ctx, "module test")
	module.AddParam("key", "module").DebugWithContext(ctx, "module test")
	module.AddParam("key", "module").InfoWithContext(ctx, "module test")
	module.AddParam("key", "module").WarningWithContext(ctx, "module test")
	module.AddParam("key", "module").ErrorWithContext(ctx, errors.New("test error"), "module test")
	subModule := module.WithSubModule("subModule1")
	subModule.AddParam("key", "module").InfoWithContext(ctx, "sub module1 test")
	subModule = subModule.WithSubModule("subModule2")
	subModule.AddParam("key", "module").InfoWithContext(ctx, "sub module2 test")
	module.AddParam("key", "module").FatalWithContext(ctx, errors.New("test error"), "module test")
	module.AddParam("key", "module").PanicWithContext(ctx, errors.New("test error"), "module test")
}

func log() {
	logg()
	logger.InfoWithContext(context.Background(), "test", "key1", 1, "key2", "ok")
}

func logg() {
	logger.Info("test", "key1", 1, "key2", "ok")
}
