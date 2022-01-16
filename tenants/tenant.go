package tenants

import (
	"context"
	"errors"
)

type tenantKey struct{}

var key = tenantKey{}

func SetTenantWithContext(c context.Context, tenant string) (context.Context, error) {
	if tenant == "" {
		return c, errors.New("Tenant is empty")
	}
	return context.WithValue(c, key, tenant), nil
}

func FromTenantContext(ctx context.Context) string {
	tenant, _ := ctx.Value(key).(string)
	return tenant
}
