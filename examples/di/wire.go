// +build wireinject

package di

import (
	"github.com/google/wire"
	"github.com/gorilla/sessions"
	"github.com/n-creativesystem/ncsfw/handler"
	"github.com/n-creativesystem/ncsfw/register"
)

func Init(store sessions.Store) (*Injector, error) {
	wire.Build(
		register.Framework,
		wire.Bind(new(handler.SocialLogin), new(*handler.SocialLoginImpl)),
		wire.Bind(new(handler.SocialHandle), new(*handler.SocialHandler)),
		handler.NewSocialLogin,
		handler.NewSocialHandler,
		Injection,
	)
	return nil, nil
}
