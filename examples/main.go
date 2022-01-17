package main

import (
	"net/http"
	"time"

	"github.com/n-creativesystem/ncsfw"
	"github.com/n-creativesystem/ncsfw/examples/di"
	"github.com/n-creativesystem/ncsfw/logger"
	"github.com/n-creativesystem/ncsfw/middleware/otel"
)

func main() {
	log := logger.New("example")
	injector, _ := di.Init(nil)
	r := ncsfw.New()
	login := r.Group("login")
	{
		login.Get("/:name", injector.SocialHandler.OAuthLogin, otel.Middleware("login request"))
		login.Get("/provider", injector.SocialHandler.GetOAuthProvider, otel.Middleware("login provider request"))
	}
	server := http.Server{
		Addr:         ":8888",
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Info("start")
	_ = server.ListenAndServe()
}
