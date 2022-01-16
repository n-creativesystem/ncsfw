package logger

import (
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n-creativesystem/ncsfw/utils"
)

func formatLogValue(value interface{}) string {
	if value == nil {
		return "nil"
	}

	if t, ok := value.(time.Time); ok {
		return t.Format(utils.TimeFormat)
	}
	value = formatStringer(value)
	switch v := value.(type) {
	case bool:
		return strconv.FormatBool(v)
	case float32:
		return strconv.FormatFloat(float64(v), utils.FloatFormat, 3, 64)
	case float64:
		return strconv.FormatFloat(v, utils.FloatFormat, 3, 64)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", value)
	case string:
		return v
	default:
		return fmt.Sprintf("%+v", v)
	}
}

func formatStringer(value interface{}) (result interface{}) {
	defer func() {
		if err := recover(); err != nil {
			if v := reflect.ValueOf(value); v.Kind() == reflect.Ptr && v.IsNil() {
				result = "nil"
			} else {
				panic(err)
			}
		}
	}()

	switch v := value.(type) {
	case time.Time:
		return v.Format(utils.TimeFormat)

	case error:
		return v.Error()

	case fmt.Stringer:
		return v.String()

	default:
		return v
	}
}

var (
	callerInitOnce     = sync.Once{}
	loggerPackage      = ""
	minimumCallerDepth = 1
)

const (
	maximumCallerDepth = 25
)

func getCaller(skip int) *runtime.Frame {
	callerInitOnce.Do(func() {
		pcs := make([]uintptr, maximumCallerDepth)
		_ = runtime.Callers(0, pcs)

		// dynamic get the package name and the minimum caller depth
		for i := 0; i < maximumCallerDepth; i++ {
			funcName := runtime.FuncForPC(pcs[i]).Name()
			if strings.Contains(funcName, "getCaller") {
				loggerPackage = getPackageName(funcName)
				break
			}
		}
		minimumCallerDepth = 4
	})
	callerPc := make([]uintptr, maximumCallerDepth)
	depth := runtime.Callers(minimumCallerDepth+skip, callerPc)
	frames := runtime.CallersFrames(callerPc[:depth])

	for f, again := frames.Next(); again; f, again = frames.Next() {
		pkg := getPackageName(f.Function)

		// If the caller isn't part of this package, we're done
		if pkg != loggerPackage {
			return &f //nolint:scopelint
		}
	}

	// if we got here, we failed to find the caller's context
	return nil
}

// getPackageName reduces a fully qualified function name to the package name
// There really ought to be to be a better way...
func getPackageName(f string) string {
	for {
		lastPeriod := strings.LastIndex(f, ".")
		lastSlash := strings.LastIndex(f, "/")
		if lastPeriod > lastSlash {
			f = f[:lastPeriod]
		} else {
			break
		}
	}

	return f
}
