package logger

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/n-creativesystem/ncsfw/utils"
	"github.com/sirupsen/logrus"
)

type Level uint32

const (
	// PanicLevel level, highest level of severity. Logs and then calls panic with the
	// message passed to Debug, Info, ...
	PanicLevel Level = iota
	// FatalLevel level. Logs and then calls `logger.Exit(1)`. It will exit even if the
	// logging level is set to Panic.
	FatalLevel
	// ErrorLevel level. Logs. Used for errors that should definitely be noted.
	// Commonly used for hooks to send errors to an error tracking service.
	ErrorLevel
	// WarnLevel level. Non-critical entries that deserve eyes.
	WarnLevel
	// InfoLevel level. General operational entries about what's going on inside the
	// application.
	InfoLevel
	// DebugLevel level. Usually only enabled when debugging. Very verbose logging.
	DebugLevel
	// TraceLevel level. Designates finer-grained informational events than the Debug.
	TraceLevel
)

type Logger interface {
	SetLevel(level Level)
	GetLevel() Level
	AddParam(key string, value interface{}) Logger
	SetSkipCaller(skip int) Logger

	Trace(message string, params ...interface{})
	Debug(message string, params ...interface{})
	Info(message string, params ...interface{})
	Warning(message string, params ...interface{})
	Error(err error, message string, params ...interface{})
	Fatal(err error, message string, params ...interface{})
	Panic(err error, message string, params ...interface{})

	TraceWithContext(ctx context.Context, message string, params ...interface{})
	DebugWithContext(ctx context.Context, message string, params ...interface{})
	InfoWithContext(ctx context.Context, message string, params ...interface{})
	WarningWithContext(ctx context.Context, message string, params ...interface{})
	ErrorWithContext(ctx context.Context, err error, message string, params ...interface{})
	FatalWithContext(ctx context.Context, err error, message string, params ...interface{})
	PanicWithContext(ctx context.Context, err error, message string, params ...interface{})
	WithSubModule(module string) Logger
	io.Writer
	// Print(args ...interface{})
	// Warn(args ...interface{})
}

var (
	defaultOption = &option{
		lvl: DebugLevel,
		reportCaller: &ReportCaller{
			File:       true,
			FileFormat: path.Base,
			Func:       true,
		},
		formatter: &logrus.JSONFormatter{
			TimestampFormat: utils.TimeFormat,
		},
		exitFunc:   os.Exit,
		hookLevels: allLevels,
	}
	allLevels = []Level{
		TraceLevel,
		DebugLevel,
		InfoLevel,
		WarnLevel,
		ErrorLevel,
		FatalLevel,
		PanicLevel,
	}
)

type defLog struct {
	log          *logrus.Entry
	prefix       string
	skip         int
	reportCaller *ReportCaller
}

type entryLog struct {
	*logrus.Entry
	log *defLog
}

func (e *entryLog) setReportCaller() *entryLog {
	if e.log.reportCaller != nil {
		f := getCaller(e.log.skip)
		if f != nil {
			fields := logrus.Fields{}
			funcVal := f.Function
			if e.log.reportCaller.FuncFormat != nil {
				funcVal = e.log.reportCaller.FuncFormat(funcVal)
			}
			f.Function = funcVal

			filename := f.File
			if e.log.reportCaller.FileFormat != nil {
				filename = e.log.reportCaller.FileFormat(filename)
			}
			f.File = filename

			fileVal := fmt.Sprintf("%s:%d", filename, f.Line)
			if e.log.reportCaller.Func && funcVal != "" {
				fields[logrus.FieldKeyFunc] = funcVal
			}
			if e.log.reportCaller.File && fileVal != "" {
				fields[logrus.FieldKeyFile] = fileVal
			}

			e.Entry = e.Entry.WithFields(fields)
		}
		e.Entry.Caller = f
	}
	return e
}

func (e *entryLog) WithContext(ctx context.Context) *entryLog {
	entity := e.Entry.WithContext(ctx)
	e.Entry = entity
	return e
}

func (e *entryLog) WithError(err error) *entryLog {
	e.Entry = e.Entry.WithError(err)
	return e
}

func New(module string, opts ...Option) Logger {
	logger := logrus.New()
	opt := &option{}
	*opt = *defaultOption
	for _, o := range opts {
		o.apply(opt)
	}
	logger.SetLevel(logrus.Level(opt.lvl))
	logger.SetFormatter(opt.formatter)
	logger.ExitFunc = opt.exitFunc
	hookLevels := make([]logrus.Level, 0, 10)
	for _, lvl := range opt.hookLevels {
		hookLevels = append(hookLevels, logrus.Level(lvl))
	}
	hook := &Hook{
		levels: hookLevels,
	}
	logger.AddHook(hook)
	return &defLog{
		log:          logger.WithField("module", module),
		skip:         0,
		reportCaller: opt.reportCaller,
	}
}

func setFields(log *defLog, params []interface{}, prefix bool) *entryLog {
	var entry = log.log.Dup()
	for i := 0; i < len(params); i += 2 {
		k, ok := params[i].(string)
		v := formatLogValue(params[i+1])
		if !ok {
			k, v = logrus.ErrorKey, formatLogValue(k)
		}
		if prefix && log.prefix != "" {
			k = fmt.Sprintf("%s.%s", log.prefix, k)
		}
		entry = entry.WithField(k, v)
	}
	return &entryLog{
		Entry: entry,
		log:   log,
	}
}

func (log *defLog) new(entry *logrus.Entry, prefix string) *defLog {
	return &defLog{
		log:          entry,
		prefix:       prefix,
		skip:         log.skip,
		reportCaller: log.reportCaller,
	}
}

func (log *defLog) Write(p []byte) (n int, err error) {
	log.Info(utils.BytesToString(p))
	return len(p), nil
}

func (log *defLog) SetLevel(level Level) {
	log.log.Logger.SetLevel(logrus.Level(level))
}

func (log *defLog) GetLevel() Level {
	return Level(log.log.Logger.GetLevel())
}

func (log *defLog) SetSkipCaller(skip int) Logger {
	log.skip = skip
	return log
}

func (log *defLog) WithSubModule(module string) Logger {
	const keyTpl = "module.%d"
	key := ""
	count := 0
	for {
		count++
		key = fmt.Sprintf(keyTpl, count)
		if _, ok := log.log.Data[key]; !ok {
			break
		}
	}
	entry := setFields(log, []interface{}{key, module}, false)
	return log.new(entry.Entry, module)
}

func (log *defLog) AddParam(key string, value interface{}) Logger {
	entry := setFields(log, []interface{}{key, value}, true)
	return log.new(entry.Entry, log.prefix)
}

func (log *defLog) Trace(message string, params ...interface{}) {
	log.TraceWithContext(context.Background(), message, params...)
}

func (log *defLog) Debug(message string, params ...interface{}) {
	log.DebugWithContext(context.Background(), message, params...)
}

func (log *defLog) Info(message string, params ...interface{}) {
	log.InfoWithContext(context.Background(), message, params...)
}

func (log *defLog) Warning(message string, params ...interface{}) {
	log.WarningWithContext(context.Background(), message, params...)
}

func (log *defLog) Error(err error, message string, params ...interface{}) {
	log.ErrorWithContext(context.Background(), err, message, params...)
}

func (log *defLog) Fatal(err error, message string, params ...interface{}) {
	log.FatalWithContext(context.Background(), err, message, params...)
}

func (log *defLog) Panic(err error, message string, params ...interface{}) {
	log.PanicWithContext(context.Background(), err, message, params...)
}

func (log *defLog) TraceWithContext(ctx context.Context, message string, params ...interface{}) {
	entry := setFields(log, params, true)
	entry.WithContext(ctx).setReportCaller().Trace(message)
}

func (log *defLog) DebugWithContext(ctx context.Context, message string, params ...interface{}) {
	entry := setFields(log, params, true)
	entry.WithContext(ctx).setReportCaller().Debug(message)
}

func (log *defLog) InfoWithContext(ctx context.Context, message string, params ...interface{}) {
	entry := setFields(log, params, true)
	entry.WithContext(ctx).setReportCaller().Info(message)
}

func (log *defLog) WarningWithContext(ctx context.Context, message string, params ...interface{}) {
	entry := setFields(log, params, true)
	entry.WithContext(ctx).setReportCaller().Warn(message)
}

func (log *defLog) ErrorWithContext(ctx context.Context, err error, message string, params ...interface{}) {
	entry := setFields(log, params, true)
	entry.WithContext(ctx).WithError(err).setReportCaller().Error(message)
}

func (log *defLog) FatalWithContext(ctx context.Context, err error, message string, params ...interface{}) {
	entry := setFields(log, params, true)
	entry.WithContext(ctx).WithError(err).setReportCaller().Fatal(message)
}

func (log *defLog) PanicWithContext(ctx context.Context, err error, message string, params ...interface{}) {
	entry := setFields(log, params, true)
	entry.WithContext(ctx).WithError(err).setReportCaller().Panic(message)
}

var std = New("default")

func GetLog() Logger                                         { return std }
func SetLevel(level Level)                                   { std.SetLevel(level) }
func GetLevel() Level                                        { return std.GetLevel() }
func Trace(message string, params ...interface{})            { std.Trace(message, params...) }
func Debug(message string, params ...interface{})            { std.Debug(message, params...) }
func Info(message string, params ...interface{})             { std.Info(message, params...) }
func Warning(message string, params ...interface{})          { std.Warning(message, params...) }
func Error(err error, message string, params ...interface{}) { std.Error(err, message, params...) }
func Fatal(err error, message string, params ...interface{}) { std.Fatal(err, message, params...) }
func Panic(err error, message string, params ...interface{}) { std.Panic(err, message, params...) }
func TraceWithContext(ctx context.Context, message string, params ...interface{}) {
	std.TraceWithContext(ctx, message, params...)
}
func DebugWithContext(ctx context.Context, message string, params ...interface{}) {
	std.DebugWithContext(ctx, message, params...)
}
func InfoWithContext(ctx context.Context, message string, params ...interface{}) {
	std.InfoWithContext(ctx, message, params...)
}
func WarningWithContext(ctx context.Context, message string, params ...interface{}) {
	std.WarningWithContext(ctx, message, params...)
}
func ErrorWithContext(ctx context.Context, err error, message string, params ...interface{}) {
	std.ErrorWithContext(ctx, err, message, params...)
}
func FatalWithContext(ctx context.Context, err error, message string, params ...interface{}) {
	std.FatalWithContext(ctx, err, message, params...)
}
func PanicWithContext(ctx context.Context, err error, message string, params ...interface{}) {
	std.PanicWithContext(ctx, err, message, params...)
}
