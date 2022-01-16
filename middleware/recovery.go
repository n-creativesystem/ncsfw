package middleware

import (
	"fmt"
	"runtime"

	"github.com/n-creativesystem/ncsfw"
)

type RecoveryConfig struct {
	StackSize         int
	DisableStackAll   bool
	DisablePrintStack bool
}

var defaultRecoveryConfig = RecoveryConfig{
	StackSize:         4 << 10,
	DisableStackAll:   false,
	DisablePrintStack: false,
}

func Recover() ncsfw.MiddlewareFunc {
	return RecoverWithConfig(RecoveryConfig{})
}

func RecoverWithConfig(cfg RecoveryConfig) ncsfw.MiddlewareFunc {
	if cfg.StackSize == 0 {
		cfg.StackSize = defaultRecoveryConfig.StackSize
	}
	return func(next ncsfw.HandlerFunc) ncsfw.HandlerFunc {
		return func(c ncsfw.Context) (e error) {
			defer func() {
				if r := recover(); r != nil {
					err, ok := r.(error)
					if !ok {
						err = fmt.Errorf("%v", r)
					}
					stack := make([]byte, cfg.StackSize)
					length := runtime.Stack(stack, !cfg.DisableStackAll)
					if !cfg.DisablePrintStack {
						msg := fmt.Sprintf("[PANIC RECOVER] %v %s\n", err, stack[:length])
						c.Logger().ErrorWithContext(c.Request().Context(), err, msg)
					}
					e = err
				}
			}()
			if err := next(c); err != nil {
				e = err
			}
			return
		}
	}
}
