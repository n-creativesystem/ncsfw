package di

import (
	"github.com/n-creativesystem/ncsfw/config"
	"github.com/n-creativesystem/ncsfw/handler"
	"github.com/n-creativesystem/ncsfw/social"
)

type Injector struct {
	Cfg           *config.Config
	SocialService social.Service
	SocialHandler handler.SocialHandle
}

func Injection(
	cfg *config.Config,
	socialService social.Service,
	socialHandler handler.SocialHandle,
) *Injector {
	return &Injector{
		Cfg:           cfg,
		SocialService: socialService,
		SocialHandler: socialHandler,
	}
}
