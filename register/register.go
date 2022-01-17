//go:build wireinject
// +build wireinject

package register

import (
	"github.com/google/wire"
	"github.com/n-creativesystem/ncsfw/config"
	"github.com/n-creativesystem/ncsfw/social"
)

var FrameworkConfig = wire.NewSet(
	config.NewConfig,
)

var Framework = wire.NewSet(
	FrameworkConfig,
	wire.Bind(new(social.Service), new(*social.SocialService)),
	social.ProvideService,
)
