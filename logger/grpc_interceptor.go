package logger

import (
	"context"
	"path"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logging "github.com/grpc-ecosystem/go-grpc-middleware/logging"
	"github.com/n-creativesystem/ncsfw/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	SystemField = "system"
	KindField   = "span.kind"
)

var (
	DefaultDurationToField = DurationToTimeMillisField
	TimestampFormat        = utils.TimeFormat
)

func DurationToTimeMillisField(duration time.Duration) (key string, value interface{}) {
	return "grpc.time_ms", durationToMilliseconds(duration)
}
func durationToMilliseconds(duration time.Duration) float32 {
	return float32(duration.Nanoseconds()/1000) / 1000
}

// UnaryServerInterceptor returns a new unary server interceptors that adds logrus.Entry to the context.
func UnaryServerInterceptor(log Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()
		newCtx := newLoggerForCall(ctx, log, info.FullMethod, startTime, TimestampFormat)

		resp, err := handler(newCtx, req)

		if !grpc_logging.DefaultDeciderMethod(info.FullMethod, err) {
			return resp, err
		}
		code := grpc_logging.DefaultErrorToCode(err)
		level := DefaultCodeToLevel(code)
		durField, durVal := DefaultDurationToField(time.Since(startTime))
		fields := map[string]interface{}{
			"grpc.code": code.String(),
			durField:    durVal,
		}
		DefaultMessageProducer(newCtx, "finished unary call with code "+code.String(), level, code, err, fields)
		return resp, err
	}
}

// StreamServerInterceptor returns a new streaming server interceptor that adds logrus.Entry to the context.
func StreamServerInterceptor(log Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		startTime := time.Now()
		newCtx := newLoggerForCall(stream.Context(), log, info.FullMethod, startTime, TimestampFormat)
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx

		err := handler(srv, wrapped)

		if !grpc_logging.DefaultDeciderMethod(info.FullMethod, err) {
			return err
		}
		code := grpc_logging.DefaultErrorToCode(err)
		level := DefaultCodeToLevel(code)
		durField, durVal := DefaultDurationToField(time.Since(startTime))
		fields := map[string]interface{}{
			"grpc.code": code.String(),
			durField:    durVal,
		}

		DefaultMessageProducer(newCtx, "finished streaming call with code "+code.String(), level, code, err, fields)
		return err
	}
}

func newLoggerForCall(ctx context.Context, log Logger, fullMethodString string, start time.Time, timestampFormat string) context.Context {
	service := path.Dir(fullMethodString)[1:]
	method := path.Base(fullMethodString)
	fields := map[string]interface{}{
		SystemField:       "grpc",
		KindField:         "server",
		"grpc.service":    service,
		"grpc.method":     method,
		"grpc.start_time": start.Format(timestampFormat),
	}
	if d, ok := ctx.Deadline(); ok {
		fields["grpc.request.deadline"] = d.Format(timestampFormat)
	}
	for k, v := range fields {
		log = log.AddParam(k, v)
	}
	return ToContext(ctx, log)
}

// DefaultCodeToLevel is the default implementation of gRPC return codes to log levels for server side.
func DefaultCodeToLevel(code codes.Code) Level {
	switch code {
	case codes.OK:
		return InfoLevel
	case codes.Canceled:
		return InfoLevel
	case codes.Unknown:
		return ErrorLevel
	case codes.InvalidArgument:
		return InfoLevel
	case codes.DeadlineExceeded:
		return WarnLevel
	case codes.NotFound:
		return InfoLevel
	case codes.AlreadyExists:
		return InfoLevel
	case codes.PermissionDenied:
		return WarnLevel
	case codes.Unauthenticated:
		return InfoLevel // unauthenticated requests can happen
	case codes.ResourceExhausted:
		return WarnLevel
	case codes.FailedPrecondition:
		return WarnLevel
	case codes.Aborted:
		return WarnLevel
	case codes.OutOfRange:
		return WarnLevel
	case codes.Unimplemented:
		return ErrorLevel
	case codes.Internal:
		return ErrorLevel
	case codes.Unavailable:
		return WarnLevel
	case codes.DataLoss:
		return ErrorLevel
	default:
		return ErrorLevel
	}
}

func DefaultMessageProducer(ctx context.Context, format string, level Level, code codes.Code, err error, fields map[string]interface{}) {
	log := Extract(ctx)
	for k, v := range fields {
		log = log.AddParam(k, v)
	}
	switch level {
	case DebugLevel:
		log.DebugWithContext(ctx, format)
	case InfoLevel:
		log.InfoWithContext(ctx, format)
	case WarnLevel:
		log.WarningWithContext(ctx, format)
	case ErrorLevel:
		log.ErrorWithContext(ctx, err, format)
	case FatalLevel:
		log.FatalWithContext(ctx, err, format)
	case PanicLevel:
		log.PanicWithContext(ctx, err, format)
	}
}
