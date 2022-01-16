package tenants

import "github.com/n-creativesystem/ncsfw"

type LoginUserTenant interface {
	GetTenant() string
}

type Lookup int

const (
	LoginUser Lookup = iota
	Header
)

type Config struct {
	Lookup Lookup

	HeaderKey string
}

func HTTPServerMiddleware() ncsfw.MiddlewareFunc {
	return HTTPServerWithConfig(Config{
		Lookup: LoginUser,
	})
}

func HTTPServerWithConfig(cfg Config) ncsfw.MiddlewareFunc {
	if cfg.Lookup == Header && cfg.HeaderKey == "" {
		cfg.HeaderKey = "x-tenant-id"
	}
	return func(next ncsfw.HandlerFunc) ncsfw.HandlerFunc {
		return func(c ncsfw.Context) error {
			r := c.Request()
			ctx := r.Context()
			var tenant string
			switch cfg.Lookup {
			case LoginUser:
				loginUser := c.GetLoginUser()
				if v, ok := loginUser.(LoginUserTenant); ok {
					tenant = v.GetTenant()
				}
			case Header:
				tenant = c.GetHeader(cfg.HeaderKey)
			}
			c.SetTenant(tenant)
			ctx, err := SetTenantWithContext(ctx, tenant)
			if err != nil {
				return err
			}
			c.SetRequest(r.WithContext(ctx))
			return next(c)
		}
	}
}
